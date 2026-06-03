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
    query_campaign_commands,
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
    result = query_commands(_db(), limit=max(1, min(limit, 1000)))
    return jsonify(result)


@app.get("/api/v1/llm-cost")
def get_llm_cost():
    """LLM usage + cost + eco metrics from llm_usage.db."""
    import os, sqlite3
    from pathlib import Path

    log_dir = app.config.get("LOG_DIR", "/data/honeypot/logs")
    db_path = os.path.join(log_dir, "llm_usage.db")

    # Pricing in EUR per million tokens
    PRICES = {
        "gpt-oss-20b":  {"input": 0.04, "output": 0.15},
        "gpt-oss-120b": {"input": 0.08, "output": 0.40},
    }
    # Rough CO2 estimate: gCO2e per token (GPU inference, efficient DC)
    CO2_G_PER_TOKEN = 0.0003

    if not Path(db_path).exists():
        return jsonify({"models": [], "total_cost_eur": 0, "total_tokens": 0,
                        "total_calls": 0, "daily": [], "eco": {}})

    try:
        from llm_providers.llm_usage import get_usage_summary, get_daily_usage_summary
        rows = get_usage_summary(db_path)
        daily_rows = get_daily_usage_summary(db_path)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    models = []
    total_cost = 0.0
    total_tokens = 0
    total_calls = 0

    for row in rows:
        mid = row.get("model_id", "")
        p = PRICES.get(mid)
        pt = row.get("prompt_tokens") or 0
        ct = row.get("completion_tokens") or 0
        tt = row.get("total_tokens") or 0
        calls = row.get("calls") or 0
        if p:
            cost = (pt * p["input"] + ct * p["output"]) / 1_000_000
        else:
            cost = (row.get("total_cost") or 0)

        total_cost += cost
        total_tokens += tt
        total_calls += calls
        models.append({
            "model_id": mid,
            "provider": row.get("provider", ""),
            "calls": calls,
            "prompt_tokens": pt,
            "completion_tokens": ct,
            "total_tokens": tt,
            "cost_eur": round(cost, 6),
            "price_input_per_mtok": p["input"] if p else None,
            "price_output_per_mtok": p["output"] if p else None,
        })

    # Daily aggregated cost
    daily = []
    for row in daily_rows:
        mid = row.get("model_id", "")
        p = PRICES.get(mid)
        pt = row.get("prompt_tokens") or 0
        ct = row.get("completion_tokens") or 0
        tt = row.get("total_tokens") or 0
        cost = (pt * p["input"] + ct * p["output"]) / 1_000_000 if p else (row.get("total_cost") or 0)
        daily.append({
            "date": row.get("day", ""),
            "model_id": mid,
            "total_tokens": tt,
            "cost_eur": round(cost, 6),
        })

    co2_g = total_tokens * CO2_G_PER_TOKEN
    eco = {
        "co2_grams": round(co2_g, 2),
        "co2_kg": round(co2_g / 1000, 4),
        "equiv_km_car": round(co2_g / 120, 3),       # 120 gCO2e/km avg EU car
        "equiv_phone_charges": round(co2_g / 8.22, 1), # 8.22 gCO2e per charge
        "equiv_searches": round(co2_g / 0.3, 0),       # 0.3 gCO2e per Google search
        "method_note": "Estimation : 0,0003 gCO2e/token (inférence GPU, DC efficace)",
    }

    return jsonify({
        "models": models,
        "total_cost_eur": round(total_cost, 6),
        "total_tokens": total_tokens,
        "total_calls": total_calls,
        "daily": daily,
        "eco": eco,
    })


@app.get("/api/v1/iocs/activity")
def get_activity():
    try:
        days = int(request.args.get("days", 30))
    except (TypeError, ValueError):
        days = 30
    result = query_activity(_db(), days=max(1, min(days, 365)))
    return jsonify(result)


# ── Report endpoints ──────────────────────────────────────────────────────────

@app.get("/api/v1/iocs/campaigns/<campaign_id>/commands")
def get_campaign_commands_endpoint(campaign_id):
    cmds = query_campaign_commands(_db(), campaign_id.upper())
    return jsonify({"commands": cmds, "total": len(cmds)})


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
