#!/usr/bin/env python3
"""
HoneyMind log processor: tail JSONL logs, enrich, push to Loki, expose metrics.

Usage:
    python main.py --log-dir /data/honeypot/logs --loki http://loki:3100 --metrics-port 9090
"""
import argparse
import gzip
import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Optional

from enricher import enrich, get_session_summary, cleanup_session, _co2_estimate
from loki_client import LokiClient
import metrics as m

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("honeymind.processor")

STATE_DB = "/tmp/honeymind_processor_state.db"
POLL_INTERVAL_S = 2.0


# ── state persistence (file offsets) ─────────────────────────────────────────

def _open_state(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE IF NOT EXISTS file_offsets (path TEXT PRIMARY KEY, offset INTEGER)")
    conn.commit()
    return conn


def _get_offset(conn: sqlite3.Connection, path: str) -> int:
    row = conn.execute("SELECT offset FROM file_offsets WHERE path=?", (path,)).fetchone()
    return row[0] if row else 0


def _set_offset(conn: sqlite3.Connection, path: str, offset: int) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO file_offsets (path, offset) VALUES (?,?)", (path, offset)
    )
    conn.commit()


# ── label building ────────────────────────────────────────────────────────────

def _build_labels(event: dict) -> dict[str, str]:
    geo = event.get("_geo") or {}
    bot = event.get("_bot") or {}
    tools = event.get("_tools") or []
    anon = event.get("_anonymization") or []
    honeypot = event.get("honeypot") or {}
    profile_flags = event.get("_profile_flags") or []
    command = event.get("command") or {}
    parser_action = command.get("parser_action") if isinstance(command, dict) else ""

    lat = geo.get("lat")
    lon = geo.get("lon")
    return {
        "job": "honeymind",
        "event_type": str(event.get("event_type") or ""),
        "service": str(event.get("service") or ""),
        "honeypot_name": str(honeypot.get("name") or ""),
        "client_ip": str((event.get("client") or {}).get("ip") or ""),
        "country": str(geo.get("country") or ""),
        "country_code": str(geo.get("country_code") or ""),
        "lat": f"{round(lat, 2)}" if lat is not None else "",
        "lon": f"{round(lon, 2)}" if lon is not None else "",
        "isp": str(geo.get("isp") or ""),
        "asn": str(geo.get("asn") or ""),
        "is_tor": str(geo.get("is_tor", False)).lower(),
        "is_vpn": str(geo.get("is_vpn", False)).lower(),
        "is_hosting": str(geo.get("is_hosting", False)).lower(),
        "is_residential": str(geo.get("is_residential", False)).lower(),
        "anonymization_type": str(geo.get("anonymization_type") or ""),
        "attack_category": str(event.get("_attack_category") or "UNKNOWN"),
        "bot_verdict": str(bot.get("verdict") or "unknown"),
        # profile_type = script_kiddie / opportunist / targeted / nation_state
        "profile_type": str(event.get("_sophistication") or ""),
        "tools": ",".join(tools) if tools else "",
        "session_id": str(event.get("session_id") or ""),
        "parser_action": str(parser_action or ""),
        "hassh": str(event.get("_hassh") or ""),
        "ssh_client": str(event.get("_ssh_client") or ""),
        "tool_match": str(event.get("_tool_match") or ""),
        "ai_trap": str(event.get("_ai_trap_triggered", False)).lower(),
        "is_ai_agent": str("ai_agent" in profile_flags).lower(),
        "business_hours": str("business_hours_local" in profile_flags).lower(),
    }


# ── metric recording ──────────────────────────────────────────────────────────

_seen_ips: dict[str, set] = {}
_active_sessions: dict[str, set] = {}
_session_last_phase: dict[str, str] = {}


def _record_metrics(event: dict) -> None:
    labels = _build_labels(event)
    service = labels["service"]
    event_type = labels["event_type"]
    category = labels["attack_category"]

    m.events_total.labels(service=service, event_type=event_type, attack_category=category).inc()

    # Unique IPs
    ip = labels["client_ip"]
    if ip:
        _seen_ips.setdefault(service, set()).add(ip)
        m.unique_ips_gauge.labels(service=service).set(len(_seen_ips[service]))

    # Active sessions
    sid = labels["session_id"]
    if event_type == "session_start" and sid:
        _active_sessions.setdefault(service, set()).add(sid)
        m.active_sessions_gauge.labels(service=service).set(len(_active_sessions.get(service, set())))
    elif event_type == "session_end" and sid:
        _active_sessions.get(service, set()).discard(sid)
        m.active_sessions_gauge.labels(service=service).set(len(_active_sessions.get(service, set())))
        summary = get_session_summary(sid)
        m.sessions_total.labels(
            service=service,
            country_code=labels["country_code"],
            verdict=summary["bot"]["verdict"],
        ).inc()
        profile_type = event.get("_sophistication") or "unknown"
        m.sophistication_total.labels(profile_type=profile_type).inc()
        m.profile_type_total.labels(profile_type=profile_type).inc()
        score = event.get("_sophistication_score") or 0
        m.sophistication_score.observe(float(score))
        cleanup_session(sid)
        _session_last_phase.pop(sid, None)

    # Attack phase transitions (kill chain progression)
    if category != "UNKNOWN" and sid:
        prev_phase = _session_last_phase.get(sid)
        if prev_phase and prev_phase != category:
            m.attack_phase_transitions_total.labels(from_phase=prev_phase, to_phase=category).inc()
        _session_last_phase[sid] = category

    # Auth metrics
    if event_type in ("auth_attempt",):
        auth = event.get("auth") or {}
        username = (event.get("client") or {}).get("username") or ""
        success = str(auth.get("success", False)).lower()
        m.auth_attempts_total.labels(service=service, username=username[:30], success=success).inc()

    # Command metrics
    if event_type == "command":
        command_obj = event.get("command") or {}
        parser_action = command_obj.get("parser_action", "unknown") if isinstance(command_obj, dict) else "unknown"
        m.commands_total.labels(
            service=service,
            attack_category=category,
            parser_action=parser_action,
        ).inc()
        raw_cmd = ""
        if isinstance(command_obj, dict):
            raw_cmd = command_obj.get("raw") or command_obj.get("normalized") or ""
        elif isinstance(command_obj, str):
            raw_cmd = command_obj
        if raw_cmd:
            m.top_commands_total.labels(command=raw_cmd[:120]).inc()
        timing = event.get("timing") or {}
        delay = timing.get("since_previous_event_ms")
        if delay is not None:
            m.inter_command_delay_ms.observe(float(delay))

    # Tool detections
    for tool in (event.get("_tools") or []):
        m.tool_detections_total.labels(tool=tool).inc()

    # Country
    if labels["country_code"]:
        m.country_events_total.labels(
            country_code=labels["country_code"],
            country=labels["country"],
        ).inc()

    # LLM ecology
    llm = event.get("llm") or {}
    if llm:
        provider = str(llm.get("provider") or "")
        model_id = str(llm.get("model_id") or "")
        pt = int(llm.get("prompt_tokens") or 0)
        ct = int(llm.get("completion_tokens") or 0)
        cost = float(llm.get("total_cost") or 0)
        currency = str(llm.get("currency") or "USD")

        if pt:
            m.llm_tokens_total.labels(provider=provider, model_id=model_id, token_type="prompt").inc(pt)
        if ct:
            m.llm_tokens_total.labels(provider=provider, model_id=model_id, token_type="completion").inc(ct)
        if cost:
            m.llm_cost_total.labels(provider=provider, model_id=model_id, currency=currency).inc(cost)

        co2, energy = _co2_estimate(pt, ct, provider)
        if co2:
            m.llm_co2_grams_total.labels(provider=provider, model_id=model_id).inc(co2)
        if energy:
            m.llm_energy_wh_total.labels(provider=provider, model_id=model_id).inc(energy)

    # File access
    file_path = event.get("_file_accessed")
    if file_path:
        m.files_accessed_total.labels(file_path=file_path[:80], attack_category=category).inc()

    # AI trap hits
    if event.get("_ai_trap_triggered"):
        for trap_id in (event.get("_ai_trap_ids") or ["unknown"]):
            m.ai_trap_hits_total.labels(trap_id=trap_id).inc()

    # HASSH / SSH client fingerprint
    ssh_client = event.get("_ssh_client") or ""
    hassh_val = event.get("_hassh") or ""
    if ssh_client or hassh_val:
        m.hassh_detections_total.labels(ssh_client=ssh_client[:60], hassh=hassh_val[:32]).inc()

    # Anonymization type
    anon_type = labels.get("anonymization_type") or ""
    if anon_type:
        m.anonymization_type_total.labels(anon_type=anon_type).inc()

    # Profile type per event
    profile_type = labels.get("profile_type") or ""
    if profile_type:
        m.profile_type_total.labels(profile_type=profile_type).inc()

    # Sophistication score
    score = event.get("_sophistication_score")
    if score is not None:
        m.sophistication_score.observe(float(score))


# ── event processing ──────────────────────────────────────────────────────────

def _ts_to_ns(ts_str: str) -> str:
    """Convert ISO timestamp to nanoseconds epoch string for Loki."""
    from datetime import datetime, timezone
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return str(int(dt.timestamp() * 1e9))
    except Exception:
        return str(int(time.time() * 1e9))


def process_event(event: dict, loki: LokiClient) -> None:
    # Normalise legacy dd-honeypot events to canonical schema
    if event.get("dd-honeypot") and event.get("schema_version") != 1:
        try:
            from canonical_log_utils import convert_legacy_event
            event = convert_legacy_event(event)
        except Exception:
            pass
    enriched = enrich(event)
    labels = _build_labels(enriched)
    _record_metrics(enriched)

    ts = enriched.get("timestamp") or ""
    ts_ns = _ts_to_ns(ts)

    # Push the enriched event to Loki as JSON line
    loki.push(labels, json.dumps(enriched, default=str, ensure_ascii=False), ts_ns)


# ── file tailing ──────────────────────────────────────────────────────────────

def _open_log(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open("r", encoding="utf-8")


def tail_file(path: Path, state: sqlite3.Connection, loki: LokiClient) -> None:
    key = str(path.resolve())
    offset = _get_offset(state, key)

    try:
        with _open_log(path) as f:
            if not path.suffix == ".gz":
                f.seek(offset)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("schema_version") == 1 or event.get("dd-honeypot"):
                    process_event(event, loki)
            if not path.suffix == ".gz":
                new_offset = f.tell()
                _set_offset(state, key, new_offset)
    except Exception as e:
        logger.warning(f"Error reading {path}: {e}")


def watch_log_dir(log_dir: Path, state: sqlite3.Connection, loki: LokiClient) -> None:
    seen_files: set[str] = set()
    while True:
        for pattern in ("*.jsonl", "*.jsonl.gz"):
            for path in sorted(log_dir.glob(pattern)):
                tail_file(path, state, loki)
                seen_files.add(str(path))
        time.sleep(POLL_INTERVAL_S)


# ── LLM usage SQLite integration ──────────────────────────────────────────────

def _process_llm_usage_db(db_path: Path, loki: LokiClient, state: sqlite3.Connection) -> None:
    """Periodically drain llm_usage rows into Loki + metrics."""
    key = f"llm_usage_db:{db_path}"
    last_id = _get_offset(state, key)

    try:
        import sqlite3 as sq3
        conn = sq3.connect(str(db_path))
        conn.row_factory = sq3.Row
        rows = conn.execute(
            "SELECT * FROM llm_usage WHERE id > ? ORDER BY id ASC", (last_id,)
        ).fetchall()
        for row in rows:
            r = dict(row)
            event = {
                "schema_version": 1,
                "timestamp": r.get("created_at", ""),
                "event_type": "llm_usage",
                "service": "llm",
                "llm": {
                    "provider": r.get("provider"),
                    "model_id": r.get("model_id"),
                    "prompt_tokens": r.get("prompt_tokens"),
                    "completion_tokens": r.get("completion_tokens"),
                    "total_tokens": r.get("total_tokens"),
                    "total_cost": r.get("total_cost"),
                    "currency": r.get("currency"),
                    "response_chars": r.get("response_chars"),
                },
            }
            process_event(event, loki)
            last_id = r["id"]
        conn.close()
        if rows:
            _set_offset(state, key, last_id)
    except Exception as e:
        logger.debug(f"llm_usage DB not available: {e}")


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="HoneyMind log processor")
    parser.add_argument("--log-dir", default="/data/honeypot/logs")
    parser.add_argument("--loki", default="http://loki:3100")
    parser.add_argument("--metrics-port", type=int, default=9090)
    parser.add_argument("--state-db", default=STATE_DB)
    args = parser.parse_args()

    log_dir = Path(args.log_dir)
    if not log_dir.exists():
        logger.warning(f"Log dir {log_dir} does not exist yet, waiting...")
        while not log_dir.exists():
            time.sleep(5)

    logger.info(f"Starting HoneyMind log processor")
    logger.info(f"  log_dir      : {log_dir}")
    logger.info(f"  loki         : {args.loki}")
    logger.info(f"  metrics_port : {args.metrics_port}")

    m.start_metrics_server(args.metrics_port)
    loki = LokiClient(args.loki)
    state = _open_state(args.state_db)

    while True:
        for pattern in ("*.jsonl", "*.jsonl.gz"):
            for path in sorted(log_dir.glob(pattern)):
                tail_file(path, state, loki)

        # Also check for llm_usage.db
        llm_db = log_dir / "llm_usage.db"
        if llm_db.exists():
            _process_llm_usage_db(llm_db, loki, state)

        loki.flush()
        time.sleep(POLL_INTERVAL_S)


if __name__ == "__main__":
    main()
