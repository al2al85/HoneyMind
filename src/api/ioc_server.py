"""
HoneyMind IOC API server — STIX 2.1 threat intelligence feed.

Reads exclusively from iocs.db (written by ioc_writer.py).
No log parsing, no analysis — just DB queries + STIX serialization.

Endpoints
---------
GET /api/v1/iocs
    STIX 2.1 bundle.  Optional filters:
      ?ip=<addr>        IOCs linked to this attacker IP
      ?campaign=<id>    IOCs linked to this campaign ID
      ?type=<ioc_type>  ipv4-addr | url | domain-name | file

GET /api/v1/iocs/ips
    All attacker IPs with campaign links and per-type IOC counts.

GET /api/v1/iocs/campaigns
    All detected campaigns with IP members and per-type IOC counts.

GET /api/v1/iocs/commands
    Top commands observed across tracked sessions.

GET /api/v1/iocs/activity
    Per-day local session activity for dashboard charts.

GET /api/v1/reports/campaign/<id>
    Get AI report for a campaign (status: not_found | generating | done | error).

POST /api/v1/reports/campaign/<id>/generate
    Trigger AI report generation for a campaign.

Usage
-----
    python src/api/ioc_server.py [--db /data/honeypot/iocs.db] [--port 5000]
"""
import argparse
import json
import logging
import os
import subprocess
import sys
import threading
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, Response, g, jsonify, request

from api.ioc_extractor import row_to_ioc
from api.ioc_store import (
    get_report,
    open_db,
    query_activity,
    query_campaigns,
    query_commands,
    query_iocs,
    query_ips,
    upsert_report,
)
from api.stix_builder import build_bundle

logger = logging.getLogger(__name__)
app = Flask(__name__)

# campaign_id → thread (to avoid duplicate generation)
_generating: dict[str, threading.Thread] = {}
_generating_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _db():
    if "db" not in g:
        g.db = open_db(app.config["DB_PATH"])
    return g.db


@app.teardown_appcontext
def _close_db(_exc):
    db = g.pop("db", None)
    if db:
        db.close()


def _stix_response(rows: list[dict]) -> Response:
    iocs = [row_to_ioc(r) for r in rows]
    bundle = build_bundle(iocs)
    return Response(
        json.dumps(bundle, ensure_ascii=False),
        content_type="application/stix+json;version=2.1",
    )


# ── IOC endpoints ─────────────────────────────────────────────────────────────

@app.get("/api/v1/iocs")
def get_iocs():
    rows = query_iocs(
        _db(),
        ip=request.args.get("ip"),
        campaign_id=request.args.get("campaign"),
        ioc_type=request.args.get("type"),
    )
    return _stix_response(rows)


@app.get("/api/v1/iocs/ips")
def get_ips():
    ips = query_ips(_db())
    return jsonify({"ips": ips, "total": len(ips)})


@app.get("/api/v1/iocs/campaigns")
def get_campaigns():
    camps = query_campaigns(_db())
    return jsonify({"campaigns": camps, "total": len(camps)})


@app.get("/api/v1/iocs/commands")
def get_commands():
    try:
        limit = int(request.args.get("limit", 25))
    except (TypeError, ValueError):
        limit = 25
    result = query_commands(_db(), limit=max(1, min(limit, 100)))
    return jsonify(result)


@app.get("/api/v1/iocs/activity")
def get_activity():
    try:
        days = int(request.args.get("days", 30))
    except (TypeError, ValueError):
        days = 30
    result = query_activity(_db(), days=max(1, min(days, 365)))
    return jsonify(result)


# ── Report endpoints ──────────────────────────────────────────────────────────

@app.get("/api/v1/reports/campaign/<campaign_id>")
def get_campaign_report(campaign_id):
    cid = campaign_id.upper()
    with _generating_lock:
        is_generating = cid in _generating

    report = get_report(_db(), cid)

    if is_generating:
        return jsonify({"campaign_id": cid, "status": "generating"})

    if not report:
        return jsonify({"campaign_id": cid, "status": "not_found"}), 404

    return jsonify(report)


@app.post("/api/v1/reports/campaign/<campaign_id>/generate")
def generate_campaign_report(campaign_id):
    cid = campaign_id.upper()

    with _generating_lock:
        if cid in _generating:
            return jsonify({"campaign_id": cid, "status": "generating"}), 202

    db_path = app.config["DB_PATH"]
    log_dir = app.config.get("LOG_DIR", "/data/honeypot/logs")
    script = app.config.get("SCRIPT_PATH", "/scripts/analyze_with_llm.py")

    def run():
        now = _now()
        # Mark as generating
        conn = open_db(db_path)
        upsert_report(conn, cid, None, "generating", None, now)
        conn.close()

        try:
            result = subprocess.run(
                [sys.executable, script, log_dir, "--campaign", cid, "--quiet"],
                capture_output=True, text=True, timeout=300,
            )
            conn = open_db(db_path)
            if result.returncode == 0 and result.stdout.strip():
                upsert_report(conn, cid, result.stdout.strip(), "done", None, _now())
            else:
                err = result.stderr.strip() or f"exit code {result.returncode}"
                upsert_report(conn, cid, None, "error", err[:500], _now())
            conn.close()
        except subprocess.TimeoutExpired:
            conn = open_db(db_path)
            upsert_report(conn, cid, None, "error", "Timeout (300s dépassé)", _now())
            conn.close()
        except Exception as exc:
            conn = open_db(db_path)
            upsert_report(conn, cid, None, "error", str(exc)[:500], _now())
            conn.close()
        finally:
            with _generating_lock:
                _generating.pop(cid, None)

    t = threading.Thread(target=run, daemon=True, name=f"report-{cid}")
    with _generating_lock:
        _generating[cid] = t
    t.start()

    return jsonify({"campaign_id": cid, "status": "generating"}), 202


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="HoneyMind IOC API")
    parser.add_argument("--db", default=os.environ.get("IOC_DB", "/data/honeypot/iocs.db"),
                        help="path to SQLite IOC database")
    parser.add_argument("--log-dir", default=os.environ.get("LOG_DIR", "/data/honeypot/logs"),
                        help="path to JSONL log directory (for report generation)")
    parser.add_argument("--script", default=os.environ.get("SCRIPT_PATH", "/scripts/analyze_with_llm.py"),
                        help="path to analyze_with_llm.py script")
    parser.add_argument("--port", type=int, default=int(os.environ.get("IOC_API_PORT", 5000)))
    parser.add_argument("--host", default=os.environ.get("IOC_API_HOST", "0.0.0.0"))
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    app.config["DB_PATH"] = args.db
    app.config["LOG_DIR"] = args.log_dir
    app.config["SCRIPT_PATH"] = args.script
    logger.info("IOC API starting on %s:%d (db=%s)", args.host, args.port, args.db)
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
