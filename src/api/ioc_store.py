"""
SQLite persistence layer for HoneyMind IOCs.

Schema
------
  iocs          — one row per (ioc_type, value), deduped
  ioc_ips       — join table: which IPs generated this IOC   (indexed on ip)
  ioc_camps     — join table: which campaigns own this IOC   (indexed on campaign_id)
  campaigns     — campaign metadata
  sessions      — per-session metadata used for campaign re-detection
  log_cursors   — tracks how far into each log file the writer has read

The writer is the only process that writes; the API server reads only.
WAL mode allows concurrent reads while the writer commits.
"""
import json
import os
import sqlite3
from collections import Counter
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

DEFAULT_DB = os.environ.get("IOC_DB", "/data/honeypot/iocs.db")

_SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS iocs (
    ioc_type          TEXT NOT NULL,
    value             TEXT NOT NULL,
    first_seen        TEXT,
    last_seen         TEXT,
    confidence        REAL NOT NULL DEFAULT 0,
    attack_categories TEXT NOT NULL DEFAULT '[]',
    session_ids       TEXT NOT NULL DEFAULT '[]',
    context           TEXT NOT NULL DEFAULT '{}',
    updated_at        TEXT NOT NULL,
    PRIMARY KEY (ioc_type, value)
);

CREATE TABLE IF NOT EXISTS ioc_ips (
    ioc_type  TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    ip        TEXT NOT NULL,
    PRIMARY KEY (ioc_type, ioc_value, ip)
);
CREATE INDEX IF NOT EXISTS idx_ioc_ips ON ioc_ips(ip);

CREATE TABLE IF NOT EXISTS ioc_camps (
    ioc_type    TEXT NOT NULL,
    ioc_value   TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    PRIMARY KEY (ioc_type, ioc_value, campaign_id)
);
CREATE INDEX IF NOT EXISTS idx_ioc_camps ON ioc_camps(campaign_id);

CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id     TEXT PRIMARY KEY,
    verdict         TEXT NOT NULL,
    confidence      REAL NOT NULL,
    ips             TEXT NOT NULL DEFAULT '[]',
    subnet          TEXT,
    asn             TEXT,
    session_count   INTEGER NOT NULL DEFAULT 0,
    time_start      TEXT,
    time_end        TEXT,
    shared_commands TEXT NOT NULL DEFAULT '[]',
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT PRIMARY KEY,
    ip          TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    commands    TEXT NOT NULL DEFAULT '[]',
    hassh       TEXT,
    user_agent  TEXT,
    updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS log_cursors (
    filepath   TEXT PRIMARY KEY,
    offset     INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
    campaign_id  TEXT PRIMARY KEY,
    content      TEXT,
    status       TEXT NOT NULL DEFAULT 'generating',
    error        TEXT,
    generated_at TEXT NOT NULL
);
"""

_MAX_SESSION_IDS = 20
_MAX_SESSION_COMMANDS = 200


def open_db(path: str = DEFAULT_DB) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


@contextmanager
def transaction(conn: sqlite3.Connection):
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


# ── Writes ────────────────────────────────────────────────────────────────────

def upsert_ioc(conn, ioc, now: str) -> None:
    """Insert or merge an IOC. attack_categories and session_ids are unioned."""
    existing = conn.execute(
        "SELECT attack_categories, session_ids FROM iocs WHERE ioc_type=? AND value=?",
        (ioc.ioc_type, ioc.value),
    ).fetchone()

    if existing:
        cats = json.loads(existing["attack_categories"])
        sids = json.loads(existing["session_ids"])
        for c in ioc.attack_categories:
            if c not in cats:
                cats.append(c)
        for s in ioc.session_ids:
            if s not in sids:
                sids.append(s)
        sids = sids[-_MAX_SESSION_IDS:]

        conn.execute("""
            UPDATE iocs SET
                first_seen        = CASE WHEN ? < first_seen OR first_seen IS NULL
                                         THEN ? ELSE first_seen END,
                last_seen         = CASE WHEN ? > last_seen OR last_seen IS NULL
                                         THEN ? ELSE last_seen END,
                confidence        = MAX(confidence, ?),
                attack_categories = ?,
                session_ids       = ?,
                context           = ?,
                updated_at        = ?
            WHERE ioc_type=? AND value=?
        """, (
            ioc.first_seen, ioc.first_seen,
            ioc.last_seen, ioc.last_seen,
            ioc.confidence,
            json.dumps(cats),
            json.dumps(sids),
            json.dumps(ioc.context),
            now,
            ioc.ioc_type, ioc.value,
        ))
    else:
        conn.execute("""
            INSERT INTO iocs
                (ioc_type, value, first_seen, last_seen, confidence,
                 attack_categories, session_ids, context, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ioc.ioc_type, ioc.value,
            ioc.first_seen, ioc.last_seen,
            ioc.confidence,
            json.dumps(ioc.attack_categories),
            json.dumps(ioc.session_ids[-_MAX_SESSION_IDS:]),
            json.dumps(ioc.context),
            now,
        ))

    for ip in ioc.source_ips:
        conn.execute(
            "INSERT OR IGNORE INTO ioc_ips(ioc_type, ioc_value, ip) VALUES (?, ?, ?)",
            (ioc.ioc_type, ioc.value, ip),
        )
    for cid in ioc.campaign_ids:
        conn.execute(
            "INSERT OR IGNORE INTO ioc_camps(ioc_type, ioc_value, campaign_id) VALUES (?, ?, ?)",
            (ioc.ioc_type, ioc.value, cid),
        )


def upsert_session(conn, session_id: str, ip: Optional[str],
                   first_seen: Optional[str], last_seen: Optional[str],
                   commands: list[str], hassh: Optional[str],
                   user_agent: Optional[str], now: str) -> None:
    existing = conn.execute(
        "SELECT commands FROM sessions WHERE session_id=?", (session_id,)
    ).fetchone()

    if existing:
        existing_cmds = json.loads(existing["commands"])
        merged = existing_cmds + [c for c in commands if c not in existing_cmds]
        merged = merged[-_MAX_SESSION_COMMANDS:]
        conn.execute("""
            UPDATE sessions SET
                last_seen  = CASE WHEN ? > last_seen OR last_seen IS NULL THEN ? ELSE last_seen END,
                commands   = ?,
                hassh      = COALESCE(hassh, ?),
                user_agent = COALESCE(user_agent, ?),
                updated_at = ?
            WHERE session_id=?
        """, (last_seen, last_seen, json.dumps(merged), hassh, user_agent, now, session_id))
    else:
        conn.execute("""
            INSERT INTO sessions
                (session_id, ip, first_seen, last_seen, commands, hassh, user_agent, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_id, ip, first_seen, last_seen,
              json.dumps(commands[-_MAX_SESSION_COMMANDS:]), hassh, user_agent, now))


def replace_campaigns(conn, campaigns, now: str) -> None:
    """Full replacement — clears all campaigns and ioc_camps, then re-inserts."""
    conn.execute("DELETE FROM ioc_camps")
    conn.execute("DELETE FROM campaigns")
    for camp in campaigns:
        conn.execute("""
            INSERT INTO campaigns
                (campaign_id, verdict, confidence, ips, subnet, asn,
                 session_count, time_start, time_end, shared_commands, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            camp.campaign_id, camp.verdict, camp.confidence,
            json.dumps(camp.ips), camp.subnet, camp.asn,
            camp.session_count, camp.time_start, camp.time_end,
            json.dumps(camp.shared_commands), now,
        ))
        for ip in camp.ips:
            # Link all IOCs from this IP to this campaign
            conn.execute("""
                INSERT OR IGNORE INTO ioc_camps (ioc_type, ioc_value, campaign_id)
                SELECT ioc_type, ioc_value, ?
                FROM ioc_ips
                WHERE ip = ?
            """, (camp.campaign_id, ip))


def get_cursor(conn, filepath: str) -> int:
    row = conn.execute(
        "SELECT offset FROM log_cursors WHERE filepath=?", (filepath,)
    ).fetchone()
    return row["offset"] if row else 0


def set_cursor(conn, filepath: str, offset: int, now: str) -> None:
    conn.execute("""
        INSERT INTO log_cursors(filepath, offset, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(filepath) DO UPDATE SET offset=excluded.offset, updated_at=excluded.updated_at
    """, (filepath, offset, now))


# ── Reads ─────────────────────────────────────────────────────────────────────

def _enrich_ioc_row(conn, row) -> dict:
    ioc_type, value = row["ioc_type"], row["value"]
    source_ips = [r["ip"] for r in conn.execute(
        "SELECT ip FROM ioc_ips WHERE ioc_type=? AND ioc_value=?", (ioc_type, value)
    ).fetchall()]
    campaign_ids = [r["campaign_id"] for r in conn.execute(
        "SELECT campaign_id FROM ioc_camps WHERE ioc_type=? AND ioc_value=?", (ioc_type, value)
    ).fetchall()]
    return {
        "ioc_type": ioc_type,
        "value": value,
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "confidence": row["confidence"],
        "attack_categories": json.loads(row["attack_categories"] or "[]"),
        "session_ids": json.loads(row["session_ids"] or "[]"),
        "context": json.loads(row["context"] or "{}"),
        "source_ips": source_ips,
        "campaign_ids": campaign_ids,
    }


def query_iocs(
    conn,
    ip: Optional[str] = None,
    campaign_id: Optional[str] = None,
    ioc_type: Optional[str] = None,
) -> list[dict]:
    where, params = [], []

    if ip:
        where.append("""EXISTS (
            SELECT 1 FROM ioc_ips
            WHERE ioc_ips.ioc_type=iocs.ioc_type
              AND ioc_ips.ioc_value=iocs.value
              AND ioc_ips.ip=?
        )""")
        params.append(ip)

    if campaign_id:
        where.append("""EXISTS (
            SELECT 1 FROM ioc_camps
            WHERE ioc_camps.ioc_type=iocs.ioc_type
              AND ioc_camps.ioc_value=iocs.value
              AND ioc_camps.campaign_id=?
        )""")
        params.append(campaign_id)

    if ioc_type:
        where.append("iocs.ioc_type=?")
        params.append(ioc_type)

    sql = "SELECT * FROM iocs"
    if where:
        sql += " WHERE " + " AND ".join(where)

    rows = conn.execute(sql, params).fetchall()
    return [_enrich_ioc_row(conn, row) for row in rows]


def query_ips(conn) -> list[dict]:
    rows = conn.execute("""
        SELECT
            ii.ip,
            MIN(iocs.first_seen)                        AS first_seen,
            MAX(iocs.last_seen)                         AS last_seen,
            GROUP_CONCAT(DISTINCT ic.campaign_id)       AS campaign_ids_raw,
            SUM(iocs.ioc_type='ipv4-addr')              AS cnt_ip,
            SUM(iocs.ioc_type='url')                    AS cnt_url,
            SUM(iocs.ioc_type='domain-name')            AS cnt_domain,
            SUM(iocs.ioc_type='file')                   AS cnt_file,
            GROUP_CONCAT(iocs.attack_categories)        AS cats_raw
        FROM ioc_ips ii
        JOIN iocs ON iocs.ioc_type=ii.ioc_type AND iocs.value=ii.ioc_value
        LEFT JOIN ioc_camps ic ON ic.ioc_type=ii.ioc_type AND ic.ioc_value=ii.ioc_value
        GROUP BY ii.ip
        ORDER BY first_seen
    """).fetchall()

    result = []
    for row in rows:
        cats: set[str] = set()
        for blob in (row["cats_raw"] or "").split(","):
            try:
                for c in json.loads(blob):
                    if c:
                        cats.add(c)
            except (json.JSONDecodeError, TypeError):
                pass
        result.append({
            "ip": row["ip"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "campaign_ids": [c for c in (row["campaign_ids_raw"] or "").split(",") if c],
            "ioc_counts": {
                "ipv4-addr": row["cnt_ip"] or 0,
                "url": row["cnt_url"] or 0,
                "domain-name": row["cnt_domain"] or 0,
                "file": row["cnt_file"] or 0,
            },
            "attack_categories": sorted(cats),
        })
    return result


def _read_session_commands(row) -> list[str]:
    try:
        commands = json.loads(row["commands"] or "[]")
    except (json.JSONDecodeError, TypeError):
        return []
    return [str(cmd).strip() for cmd in commands if str(cmd).strip()]


def _top_command_counts(rows, limit: int = 25) -> list[dict]:
    counts: Counter[str] = Counter()
    for row in rows:
        counts.update(_read_session_commands(row))
    return [
        {"command": command, "count": count}
        for command, count in counts.most_common(limit)
    ]


def query_commands(conn, limit: int = 25) -> dict:
    """Return commands observed across all tracked sessions."""
    rows = conn.execute("SELECT commands FROM sessions").fetchall()
    all_commands = _top_command_counts(rows, limit=10_000)
    top_commands = all_commands[:limit]
    return {
        "commands": top_commands,
        "total": sum(item["count"] for item in all_commands),
    }


def _query_commands_for_ips(conn, ips: list[str], limit: int = 25) -> list[dict]:
    if not ips:
        return []
    placeholders = ",".join("?" for _ in ips)
    rows = conn.execute(
        f"SELECT commands FROM sessions WHERE ip IN ({placeholders})",
        ips,
    ).fetchall()
    return _top_command_counts(rows, limit=limit)


def _query_session_counts_for_ips(
    conn,
    ips: list[str],
    time_start: Optional[str] = None,
    time_end: Optional[str] = None,
) -> dict[str, int]:
    if not ips:
        return {}
    placeholders = ",".join("?" for _ in ips)
    where = [f"ip IN ({placeholders})"]
    params: list[str] = list(ips)
    if time_start:
        where.append("(last_seen IS NULL OR last_seen >= ?)")
        params.append(time_start)
    if time_end:
        where.append("(first_seen IS NULL OR first_seen <= ?)")
        params.append(time_end)
    rows = conn.execute(
        f"SELECT ip, COUNT(*) AS cnt FROM sessions WHERE {' AND '.join(where)} GROUP BY ip",
        params,
    ).fetchall()
    return {row["ip"]: row["cnt"] for row in rows}


def _parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _campaign_status(time_end: Optional[str], inactive_after_minutes: int = 60) -> str:
    end = _parse_iso_datetime(time_end)
    if not end:
        return "active"
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=inactive_after_minutes)
    return "active" if end >= cutoff else "closed"


def query_activity(conn, days: int = 30) -> dict:
    """Return per-day session activity from the local sessions table."""
    days = max(1, min(days, 365))
    today = datetime.now(timezone.utc).date()
    start = today - timedelta(days=days - 1)
    counts = {start + timedelta(days=i): 0 for i in range(days)}

    rows = conn.execute("""
        SELECT substr(COALESCE(first_seen, last_seen, updated_at), 1, 10) AS day,
               COUNT(*) AS sessions
        FROM sessions
        WHERE COALESCE(first_seen, last_seen, updated_at) IS NOT NULL
          AND substr(COALESCE(first_seen, last_seen, updated_at), 1, 10) >= ?
        GROUP BY day
    """, (start.isoformat(),)).fetchall()

    for row in rows:
        try:
            day = date.fromisoformat(row["day"])
        except (TypeError, ValueError):
            continue
        if day in counts:
            counts[day] = row["sessions"]

    activity = [
        {"day": index + 1, "date": day.isoformat(), "attacks": sessions}
        for index, (day, sessions) in enumerate(counts.items())
    ]
    return {"activity": activity, "total": sum(item["attacks"] for item in activity)}


def query_campaigns(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM campaigns ORDER BY confidence DESC"
    ).fetchall()
    result = []
    for row in rows:
        cid = row["campaign_id"]
        ips = json.loads(row["ips"] or "[]")
        observed_commands = _query_commands_for_ips(conn, ips)
        ip_session_counts = _query_session_counts_for_ips(
            conn,
            ips,
            time_start=row["time_start"],
            time_end=row["time_end"],
        )
        counts = conn.execute("""
            SELECT ioc_type, COUNT(*) AS cnt
            FROM iocs
            WHERE EXISTS (
                SELECT 1 FROM ioc_camps
                WHERE ioc_camps.ioc_type=iocs.ioc_type
                  AND ioc_camps.ioc_value=iocs.value
                  AND ioc_camps.campaign_id=?
            )
            GROUP BY ioc_type
        """, (cid,)).fetchall()
        result.append({
            "campaign_id": cid,
            "verdict": row["verdict"],
            "confidence": row["confidence"],
            "ips": ips,
            "subnet": row["subnet"],
            "asn": row["asn"],
            "session_count": row["session_count"],
            "time_start": row["time_start"],
            "time_end": row["time_end"],
            "status": _campaign_status(row["time_end"]),
            "shared_commands": json.loads(row["shared_commands"] or "[]"),
            "observed_commands": observed_commands,
            "command_count": sum(item["count"] for item in observed_commands),
            "ip_session_counts": ip_session_counts,
            "ioc_counts": {r["ioc_type"]: r["cnt"] for r in counts},
        })
    return result


def load_sessions_for_campaign_detection(conn) -> dict[str, list[dict]]:
    """
    Reconstruct minimal fake-event sessions from the sessions table,
    compatible with detect_campaigns().
    """
    rows = conn.execute("SELECT * FROM sessions").fetchall()
    sessions: dict[str, list[dict]] = {}
    for row in rows:
        ip = row["ip"]
        if not ip:
            continue
        fake_events: list[dict] = [{
            "client": {"ip": ip},
            "timestamp": row["first_seen"],
        }]
        if row["hassh"]:
            fake_events[0]["ssh_fingerprint"] = {"hassh": row["hassh"]}
        if row["user_agent"]:
            fake_events[0]["http-request"] = {"headers": {"User-Agent": row["user_agent"]}}
        for cmd in json.loads(row["commands"] or "[]"):
            fake_events.append({
                "client": {"ip": ip},
                "timestamp": row["last_seen"],
                "command": {"raw": cmd},
            })
        sessions[row["session_id"]] = fake_events
    return sessions


# ── Reports ───────────────────────────────────────────────────────────────────

def get_report(conn, campaign_id: str) -> Optional[dict]:
    row = conn.execute(
        "SELECT campaign_id, content, status, error, generated_at FROM reports WHERE campaign_id=?",
        (campaign_id,)
    ).fetchone()
    if not row:
        return None
    return {
        "campaign_id": row["campaign_id"],
        "content": row["content"],
        "status": row["status"],
        "error": row["error"],
        "generated_at": row["generated_at"],
    }


def upsert_report(conn, campaign_id: str, content: Optional[str],
                  status: str, error: Optional[str], now: str) -> None:
    conn.execute("""
        INSERT INTO reports (campaign_id, content, status, error, generated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(campaign_id) DO UPDATE SET
            content=excluded.content, status=excluded.status,
            error=excluded.error, generated_at=excluded.generated_at
    """, (campaign_id, content, status, error, now))
    conn.commit()


def query_campaign_commands(conn, campaign_id: str, limit: int = 100) -> list[dict]:
    """All commands observed in sessions whose IP belongs to this campaign, grouped by count."""
    row = conn.execute(
        "SELECT ips FROM campaigns WHERE campaign_id=?", (campaign_id,)
    ).fetchone()
    if not row:
        return []
    ips = json.loads(row["ips"] or "[]")
    if not ips:
        return []

    placeholders = ",".join("?" * len(ips))
    rows = conn.execute(
        f"SELECT commands FROM sessions WHERE ip IN ({placeholders})", ips
    ).fetchall()

    from collections import Counter
    counts: Counter = Counter()
    for r in rows:
        for cmd in json.loads(r["commands"] or "[]"):
            cmd = cmd.strip()
            if cmd:
                counts[cmd] += 1

    return [
        {"command": cmd, "count": cnt}
        for cmd, cnt in counts.most_common(limit)
    ]
