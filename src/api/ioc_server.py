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

Usage
-----
    python src/api/ioc_server.py [--db /data/honeypot/iocs.db] [--port 5000]
"""
import argparse
import json
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, Response, g, jsonify, request

from api.ioc_extractor import row_to_ioc
from api.ioc_store import open_db, query_campaigns, query_commands, query_iocs, query_ips
from api.stix_builder import build_bundle

logger = logging.getLogger(__name__)
app = Flask(__name__)


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


def main():
    parser = argparse.ArgumentParser(description="HoneyMind IOC API")
    parser.add_argument("--db", default=os.environ.get("IOC_DB", "/data/honeypot/iocs.db"),
                        help="path to SQLite IOC database (default: $IOC_DB or /data/honeypot/iocs.db)")
    parser.add_argument("--port", type=int, default=int(os.environ.get("IOC_API_PORT", 5000)))
    parser.add_argument("--host", default=os.environ.get("IOC_API_HOST", "0.0.0.0"))
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    app.config["DB_PATH"] = args.db
    logger.info("IOC API starting on %s:%d (db=%s)", args.host, args.port, args.db)
    app.run(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
