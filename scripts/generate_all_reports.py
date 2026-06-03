#!/usr/bin/env python3
"""
Generate AI reports for all campaigns that don't have one yet.

Usage:
    python scripts/generate_all_reports.py [--api http://localhost:5000] [--dry-run] [--force]

Options:
    --api URL     Base URL of the IOC API (default: http://localhost:5000)
    --dry-run     Print what would be generated without triggering anything
    --force       Re-generate even for campaigns that already have a report
    --parallel N  Number of concurrent generations (default: 1)
"""
import argparse
import sys
import time
import urllib.request
import urllib.error
import json


def _get(url):
    with urllib.request.urlopen(url, timeout=15) as r:
        return json.loads(r.read())


def _post(url):
    req = urllib.request.Request(url, data=b"", method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read()), r.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code


def _poll(api, cid, timeout=300):
    """Wait until the report is done or errored. Returns final status."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data = _get(f"{api}/api/v1/reports/campaign/{cid}")
            status = data.get("status")
            if status in ("done", "error", "not_found"):
                return status
        except Exception:
            pass
        time.sleep(5)
    return "timeout"


def main():
    parser = argparse.ArgumentParser(description="Generate missing AI reports for all campaigns")
    parser.add_argument("--api",      default="http://localhost:5000", help="IOC API base URL")
    parser.add_argument("--dry-run",  action="store_true")
    parser.add_argument("--force",    action="store_true", help="Re-generate existing reports too")
    parser.add_argument("--parallel", type=int, default=1, metavar="N",
                        help="Max concurrent generations (default: 1)")
    args = parser.parse_args()

    api = args.api.rstrip("/")

    # Fetch all campaigns
    print(f"Fetching campaigns from {api}…")
    try:
        data = _get(f"{api}/api/v1/iocs/campaigns")
    except Exception as e:
        print(f"Error: cannot reach API — {e}", file=sys.stderr)
        sys.exit(1)

    campaigns = data.get("campaigns", [])
    print(f"Found {len(campaigns)} campaign(s).")

    # Determine which need a report
    to_generate = []
    for c in campaigns:
        cid = c["campaign_id"]
        try:
            report = _get(f"{api}/api/v1/reports/campaign/{cid}")
            status = report.get("status", "not_found")
        except urllib.error.HTTPError as e:
            status = "not_found" if e.code == 404 else "error"
        except Exception:
            status = "error"

        needs = args.force or status in ("not_found", "error")
        verdict = c.get("verdict", "?")
        ips_n = len(c.get("ips", []))
        marker = "→ GENERATE" if needs else f"  skip ({status})"
        print(f"  {cid}  {verdict:<22}  {ips_n} IP(s)  {marker}")
        if needs:
            to_generate.append(cid)

    if not to_generate:
        print("\nNothing to generate.")
        return

    print(f"\n{len(to_generate)} report(s) to generate.")
    if args.dry_run:
        print("[dry-run] stopping here.")
        return

    # Generate — sequential by default, or N at a time
    import threading, queue

    q = queue.Queue()
    for cid in to_generate:
        q.put(cid)

    results = {}
    lock = threading.Lock()

    def worker():
        while True:
            try:
                cid = q.get_nowait()
            except queue.Empty:
                return
            print(f"  [{cid}] Triggering generation…")
            try:
                body, code = _post(f"{api}/api/v1/reports/campaign/{cid}/generate")
                if code not in (200, 202):
                    with lock:
                        results[cid] = "error (trigger failed)"
                    print(f"  [{cid}] ✗ trigger failed ({code})")
                    q.task_done()
                    continue
            except Exception as e:
                with lock:
                    results[cid] = f"error ({e})"
                print(f"  [{cid}] ✗ {e}")
                q.task_done()
                continue

            status = _poll(api, cid)
            with lock:
                results[cid] = status
            icon = "✓" if status == "done" else "✗"
            print(f"  [{cid}] {icon} {status}")
            q.task_done()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(args.parallel)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    done  = sum(1 for s in results.values() if s == "done")
    error = sum(1 for s in results.values() if s != "done")
    print(f"\nDone: {done} ✓   Failed: {error} ✗")
    if error:
        sys.exit(1)


if __name__ == "__main__":
    main()
