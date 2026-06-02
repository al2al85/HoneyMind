"""
HoneyMind IOC writer — tails JSONL log files and incrementally populates iocs.db.

Processing model
----------------
  Every POLL_INTERVAL seconds:
    1. For each *.jsonl[.gz] in log_dir, read new lines since last cursor offset.
    2. For each new event:
       - Ensure the source IP has an IOC record.
       - On wget/curl commands: extract URL, domain, and file hash (if downloaded).
       - On scp_upload events: extract file hash from upload_dir.
       - Update session metadata (commands, hassh, timing).
    3. Write all changes in a single SQLite transaction, then advance cursors.

  Every CAMPAIGN_INTERVAL seconds (independent timer):
    - Re-run campaign detection from the sessions table.
    - Replace campaigns table + ioc_camps join table atomically.

Usage
-----
    python src/api/ioc_writer.py [--log-dir ...] [--db ...] [--poll 15] [--campaign-interval 120]
"""
import argparse
import gzip
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analysis.attack_classifier import classify_command
from analysis.campaign_detector import detect_campaigns
from api.ioc_extractor import (
    IOC,
    URL_RE,
    cmd_str,
    domain_from_url,
    event_ip,
    file_sha256,
    filename_from_url,
)
from api.ioc_store import (
    get_cursor,
    load_sessions_for_campaign_detection,
    open_db,
    replace_campaigns,
    set_cursor,
    transaction,
    upsert_ioc,
    upsert_session,
)

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _open_log(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open("r", encoding="utf-8")


# ── Per-event IOC extraction ───────────────────────────────────────────────────

def _iocs_from_event(
    event: dict,
    ip: str,
    sid: str,
    ts: str,
    download_dir: str,
    upload_dir: str,
) -> list[IOC]:
    iocs: list[IOC] = []

    # SCP upload: file dropped by attacker onto the honeypot
    details = event.get("details") or {}
    if details.get("event") == "scp_upload":
        filename = details.get("filename")
        if filename:
            digest = file_sha256(os.path.join(upload_dir, os.path.basename(filename)))
            if digest:
                iocs.append(IOC(
                    ioc_type="file", value=digest,
                    first_seen=ts, last_seen=ts,
                    confidence=0.99,
                    attack_categories=["LATERAL_MOVEMENT"],
                    source_ips=[ip], campaign_ids=[], session_ids=[sid],
                    context={
                        "filename": os.path.basename(filename),
                        "sha256": digest,
                        "transfer_method": "scp",
                    },
                ))
        return iocs

    cmd = cmd_str(event)
    if not cmd:
        return iocs

    if not re.search(r'\b(wget|curl)\b', cmd):
        return iocs

    cat = classify_command(cmd).value

    for url in URL_RE.findall(cmd):
        iocs.append(IOC(
            ioc_type="url", value=url,
            first_seen=ts, last_seen=ts,
            confidence=0.90,
            attack_categories=[cat] if cat != "UNKNOWN" else [],
            source_ips=[ip], campaign_ids=[], session_ids=[sid],
            context={"command": cmd},
        ))
        domain = domain_from_url(url)
        if domain:
            iocs.append(IOC(
                ioc_type="domain-name", value=domain,
                first_seen=ts, last_seen=ts,
                confidence=0.85,
                attack_categories=[cat] if cat != "UNKNOWN" else [],
                source_ips=[ip], campaign_ids=[], session_ids=[sid],
                context={"source_url": url},
            ))
        fname = filename_from_url(url)
        if fname:
            digest = file_sha256(os.path.join(download_dir, fname))
            if digest:
                iocs.append(IOC(
                    ioc_type="file", value=digest,
                    first_seen=ts, last_seen=ts,
                    confidence=0.98,
                    attack_categories=[cat] if cat != "UNKNOWN" else [],
                    source_ips=[ip], campaign_ids=[], session_ids=[sid],
                    context={
                        "filename": fname,
                        "sha256": digest,
                        "source_url": url,
                        "transfer_method": "wget/curl",
                    },
                ))

    return iocs


# ── Log file processing ────────────────────────────────────────────────────────

def process_file(
    conn,
    path: Path,
    download_dir: str,
    upload_dir: str,
    now: str,
) -> int:
    """Read new lines from path since stored cursor. Returns number of events processed."""
    offset = get_cursor(conn, str(path))
    file_size = path.stat().st_size
    if file_size <= offset:
        return 0

    new_events = 0
    # session_id → {ip, first_seen, last_seen, commands, hassh, user_agent}
    session_buf: dict[str, dict] = {}

    with _open_log(path) as f:
        f.seek(offset)
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("schema_version") != 1 and not event.get("dd-honeypot"):
                continue

            ip = event_ip(event)
            if not ip:
                continue

            sid = event.get("session_id") or event.get("session-id") or "unknown"
            ts = event.get("timestamp") or event.get("time") or now

            # --- IP IOC (ensure exists) ---
            upsert_ioc(conn, IOC(
                ioc_type="ipv4-addr", value=ip,
                first_seen=ts, last_seen=ts,
                confidence=0.95,
                attack_categories=[],
                source_ips=[ip], campaign_ids=[], session_ids=[sid],
            ), now)

            # --- URL / domain / file IOCs ---
            for ioc in _iocs_from_event(event, ip, sid, ts, download_dir, upload_dir):
                upsert_ioc(conn, ioc, now)

            # --- Attack category → backfill onto IP IOC ---
            cmd = cmd_str(event)
            if cmd:
                cat = classify_command(cmd).value
                if cat != "UNKNOWN":
                    # read-modify-write the IP IOC's attack_categories
                    row = conn.execute(
                        "SELECT attack_categories FROM iocs WHERE ioc_type='ipv4-addr' AND value=?",
                        (ip,)
                    ).fetchone()
                    if row:
                        cats = json.loads(row["attack_categories"])
                        if cat not in cats:
                            cats.append(cat)
                            conn.execute(
                                "UPDATE iocs SET attack_categories=?, updated_at=? "
                                "WHERE ioc_type='ipv4-addr' AND value=?",
                                (json.dumps(cats), now, ip)
                            )

            # --- Session metadata (for campaign detection) ---
            if sid not in session_buf:
                session_buf[sid] = {
                    "ip": ip, "first_seen": ts, "last_seen": ts,
                    "commands": [], "hassh": None, "user_agent": None,
                }
            buf = session_buf[sid]
            buf["last_seen"] = max(buf["last_seen"], ts)
            if cmd:
                buf["commands"].append(cmd)
            fp = event.get("ssh_fingerprint") or {}
            if fp.get("hassh") and not buf["hassh"]:
                buf["hassh"] = fp["hassh"]
            ua = ((event.get("http-request") or {}).get("headers") or {}).get("User-Agent")
            if ua and not buf["user_agent"]:
                buf["user_agent"] = ua

            new_events += 1

        new_offset = f.tell() if hasattr(f, "tell") else file_size

    # Flush session metadata
    for sid, buf in session_buf.items():
        upsert_session(
            conn, sid, buf["ip"], buf["first_seen"], buf["last_seen"],
            buf["commands"], buf["hassh"], buf["user_agent"], now,
        )

    set_cursor(conn, str(path), new_offset, now)
    return new_events


# ── Main loop ─────────────────────────────────────────────────────────────────

def run(
    log_dir: str,
    db_path: str,
    download_dir: str,
    upload_dir: str,
    poll_interval: int,
    campaign_interval: int,
) -> None:
    conn = open_db(db_path)
    last_campaign_run = 0.0

    logger.info("Writer started — log_dir=%s db=%s poll=%ds campaign=%ds",
                log_dir, db_path, poll_interval, campaign_interval)

    while True:
        now = _now()
        log_path = Path(log_dir)
        total_events = 0

        log_files = sorted(log_path.glob("*.jsonl")) + sorted(log_path.glob("*.jsonl.gz"))

        if log_files:
            with transaction(conn):
                for path in log_files:
                    n = process_file(conn, path, download_dir, upload_dir, now)
                    total_events += n

            if total_events:
                logger.info("Processed %d new events from %d files", total_events, len(log_files))

        # Campaign detection runs on its own timer
        if time.time() - last_campaign_run >= campaign_interval:
            sessions = load_sessions_for_campaign_detection(conn)
            if sessions:
                campaigns = detect_campaigns(sessions)
                with transaction(conn):
                    replace_campaigns(conn, campaigns, now)
                logger.info("Campaign detection: %d campaigns from %d sessions",
                            len(campaigns), len(sessions))
            last_campaign_run = time.time()

        time.sleep(poll_interval)


def main() -> None:
    parser = argparse.ArgumentParser(description="HoneyMind IOC writer")
    parser.add_argument("--log-dir", default=os.environ.get("LOG_DIR", "/data/honeypot/logs"),
                        help="path to JSONL log directory (default: $LOG_DIR or /data/honeypot/logs)")
    parser.add_argument("--db", default=os.environ.get("IOC_DB", "/data/honeypot/iocs.db"),
                        help="path to SQLite IOC database (default: $IOC_DB or /data/honeypot/iocs.db)")
    parser.add_argument("--download-dir", default=os.environ.get("HONEYPOT_DOWNLOAD_DIR", "/data/honeypot/downloads"))
    parser.add_argument("--upload-dir", default=os.environ.get("HONEYPOT_UPLOAD_DIR", "/data/honeypot/uploads"))
    parser.add_argument("--poll", type=int, default=int(os.environ.get("IOC_POLL_INTERVAL", 15)),
                        help="seconds between log polls (default: 15)")
    parser.add_argument("--campaign-interval", type=int,
                        default=int(os.environ.get("IOC_CAMPAIGN_INTERVAL", 120)),
                        help="seconds between campaign re-detections (default: 120)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run(
        log_dir=args.log_dir,
        db_path=args.db,
        download_dir=args.download_dir,
        upload_dir=args.upload_dir,
        poll_interval=args.poll,
        campaign_interval=args.campaign_interval,
    )


if __name__ == "__main__":
    main()
