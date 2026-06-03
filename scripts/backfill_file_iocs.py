#!/usr/bin/env python3
"""
Backfill file IOCs for SCP/wget transfers that happened before the logging fix.

Two passes:
  1. Reset log_cursors so ioc_writer reprocesses all JSONL logs from scratch.
     This recovers file IOCs for wget/curl (commands were logged, files on disk).
  2. Scan upload_dir and download_dir for files not already in the IOC DB.
     This recovers SFTP uploads that were never logged as events.

Usage:
    python scripts/backfill_file_iocs.py [--db PATH] [--upload-dir PATH] [--download-dir PATH] [--dry-run]

The script is idempotent: running it multiple times is safe.
"""
import argparse
import gzip
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import sqlite3


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _open_log(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open("r", encoding="utf-8")


def _extract_ip_for_file(log_dir: Path, filename: str) -> str | None:
    """
    Scan JSONL logs for an scp_upload event that matches filename.
    Returns the first matching client IP found.
    """
    for log_file in sorted(log_dir.glob("*.jsonl")) + sorted(log_dir.glob("*.jsonl.gz")):
        try:
            with _open_log(log_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    details = event.get("details") or {}
                    if details.get("event") == "scp_upload" and details.get("filename") == filename:
                        ip = (event.get("client") or {}).get("ip") or event.get("client_ip")
                        if ip:
                            return ip
        except Exception:
            continue
    return None


def _upsert_file_ioc(conn, digest: str, filename: str, source_ip: str | None,
                     transfer_method: str, ts: str, dry_run: bool) -> bool:
    """Insert file IOC if not already present. Returns True if inserted."""
    existing = conn.execute(
        "SELECT 1 FROM iocs WHERE ioc_type='file' AND value=?", (digest,)
    ).fetchone()
    if existing:
        return False

    if dry_run:
        print(f"  [dry-run] would create file IOC: {filename} ({digest[:12]}…) ip={source_ip}")
        return True

    n = _now()
    conn.execute("""
        INSERT INTO iocs
            (ioc_type, value, first_seen, last_seen, confidence,
             attack_categories, session_ids, context, updated_at)
        VALUES ('file', ?, ?, ?, 0.90, '[]', '[]', ?, ?)
        ON CONFLICT(ioc_type, value) DO NOTHING
    """, (
        digest, ts, ts,
        json.dumps({"filename": filename, "sha256": digest, "transfer_method": transfer_method}),
        n,
    ))

    if source_ip:
        conn.execute(
            "INSERT OR IGNORE INTO ioc_ips (ioc_type, ioc_value, ip) VALUES ('file', ?, ?)",
            (digest, source_ip),
        )
    return True


def reset_cursors(conn, dry_run: bool) -> int:
    rows = conn.execute("SELECT COUNT(*) FROM log_cursors").fetchone()[0]
    if dry_run:
        print(f"[dry-run] would reset {rows} log cursor(s) to 0")
        return rows
    conn.execute("UPDATE log_cursors SET offset=0")
    conn.commit()
    return rows


def backfill_dir(conn, directory: Path, transfer_method: str,
                 log_dir: Path | None, dry_run: bool) -> int:
    if not directory.exists():
        print(f"  {directory} does not exist, skipping.")
        return 0

    created = 0
    files = [f for f in directory.iterdir() if f.is_file()]
    for f in files:
        digest = _sha256(f)
        if not digest:
            continue

        source_ip = None
        if log_dir:
            source_ip = _extract_ip_for_file(log_dir, f.name)

        ts = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        if _upsert_file_ioc(conn, digest, f.name, source_ip, transfer_method, ts, dry_run):
            created += 1
            print(f"  + {f.name}  sha256={digest[:16]}…  ip={source_ip or '(unknown)'}")

    if not dry_run and created:
        conn.commit()
    return created


def main():
    parser = argparse.ArgumentParser(description="Backfill file IOCs from existing uploads/downloads")
    parser.add_argument("--db",          default=os.environ.get("IOC_DB", "/data/honeypot/iocs.db"))
    parser.add_argument("--log-dir",     default=os.environ.get("LOG_DIR", "/data/honeypot/logs"))
    parser.add_argument("--upload-dir",  default=os.environ.get("HONEYPOT_UPLOAD_DIR", "/data/honeypot/uploads"))
    parser.add_argument("--download-dir",default=os.environ.get("HONEYPOT_DOWNLOAD_DIR", "/data/honeypot/downloads"))
    parser.add_argument("--dry-run",     action="store_true", help="Print what would be done without writing")
    parser.add_argument("--no-cursor-reset", action="store_true", help="Skip resetting log cursors")
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    log_dir = Path(args.log_dir)

    # ── 1. Reset log cursors so ioc_writer reprocesses all JSONL ──────────────
    if not args.no_cursor_reset:
        print("=== Step 1: Reset log cursors (wget/curl backfill via ioc_writer) ===")
        n = reset_cursors(conn, args.dry_run)
        print(f"  Reset {n} cursor(s). ioc_writer will reprocess all logs on next poll.")
    else:
        print("=== Step 1: Skipped (--no-cursor-reset) ===")

    # ── 2. Scan upload_dir (SCP/SFTP — may never have had a log event) ────────
    print(f"\n=== Step 2: Scan upload dir: {args.upload_dir} ===")
    u = backfill_dir(conn, Path(args.upload_dir), "scp", log_dir, args.dry_run)
    print(f"  {u} new file IOC(s) created from uploads.")

    # ── 3. Scan download_dir (wget/curl — safety net if cursor reset isn't enough) ──
    print(f"\n=== Step 3: Scan download dir: {args.download_dir} ===")
    d = backfill_dir(conn, Path(args.download_dir), "wget/curl", log_dir, args.dry_run)
    print(f"  {d} new file IOC(s) created from downloads.")

    conn.close()

    print(f"\nDone. {u + d} total new IOC(s) created.")
    if not args.no_cursor_reset and not args.dry_run:
        print("Wait for ioc_writer to reprocess logs (~15 s), then campaign detection (~120 s).")
        print("Or restart ioc-writer container to trigger immediately.")


if __name__ == "__main__":
    main()
