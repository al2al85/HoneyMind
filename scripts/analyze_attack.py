#!/usr/bin/env python3
"""
Analyze HoneyMind attack logs: timeline per session + categorization.

Usage:
    python scripts/analyze_attack.py [log_dir]
    python scripts/analyze_attack.py [log_dir] --session <session-id>
    python scripts/analyze_attack.py [log_dir] --ip <client-ip>
"""
import argparse
import gzip
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from attack_classifier import Category, classify_event, label, _extract_command


# ── helpers ──────────────────────────────────────────────────────────────────

def _open(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open("r", encoding="utf-8")


def _iter_events(log_dir: Path):
    for path in sorted(log_dir.glob("*.jsonl")) + sorted(log_dir.glob("*.jsonl.gz")):
        with _open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("dd-honeypot"):
                    yield event


def _command_display(event: dict) -> str:
    cmd = _extract_command(event)
    if cmd:
        return cmd[:120]
    if "login" in event:
        login = event["login"]
        user = login.get("username", "?")
        success = "✓" if login.get("success") else "✗"
        pwd = login.get("password", "")
        return f"login user={user} password={pwd} [{success}]"
    return "(no command)"


# ── session timeline ──────────────────────────────────────────────────────────

def build_sessions(log_dir: Path) -> dict[str, list[dict]]:
    sessions: dict[str, list[dict]] = defaultdict(list)
    for event in _iter_events(log_dir):
        sid = event.get("session-id") or "unknown"
        sessions[sid].append(event)
    for sid in sessions:
        sessions[sid].sort(key=lambda e: (e.get("seq") or 0, e.get("time") or ""))
    return sessions


def print_session_timeline(sid: str, events: list[dict]):
    if not events:
        return

    first = events[0]
    ip = first.get("client_ip") or "?"
    protocol = first.get("protocol") or first.get("type") or "?"
    port = first.get("port") or "?"
    username = first.get("username") or "?"
    time_start = first.get("time", "")[:19]

    categories_seen = set()
    for e in events:
        categories_seen.add(classify_event(e))

    print(f"\n{'═'*70}")
    print(f"  Session : {sid}")
    print(f"  IP      : {ip}  |  protocol: {protocol}:{port}  |  user: {username}")
    print(f"  Start   : {time_start}  |  events: {len(events)}")
    print(f"  Phases  : {' → '.join(label(c) for c in _phase_order(categories_seen))}")
    print(f"{'─'*70}")

    for event in events:
        cat = classify_event(event)
        seq = event.get("seq", "?")
        t = (event.get("time") or "")[:19]
        elapsed = event.get("elapsed_ms")
        elapsed_str = f"+{elapsed}ms" if elapsed is not None else ""
        cmd = _command_display(event)
        cat_label = label(cat).ljust(18)
        print(f"  [{seq:>3}] {t} {elapsed_str:>8}  {cat_label}  {cmd}")

    print(f"{'═'*70}")


def _phase_order(categories: set) -> list[Category]:
    order = [
        Category.LOGIN,
        Category.RECON,
        Category.DISCOVERY,
        Category.CREDENTIAL_ACCESS,
        Category.EXECUTION,
        Category.PERSISTENCE,
        Category.PRIVILEGE_ESCALATION,
        Category.LATERAL_MOVEMENT,
        Category.EXFILTRATION,
        Category.IMPACT,
        Category.UNKNOWN,
    ]
    return [c for c in order if c in categories]


# ── global summary ────────────────────────────────────────────────────────────

def print_summary(sessions: dict[str, list[dict]]):
    total_events = sum(len(e) for e in sessions.values())
    all_events = [e for events in sessions.values() for e in events]

    ip_counts: dict[str, int] = defaultdict(int)
    category_counts: dict[Category, int] = defaultdict(int)
    protocol_counts: dict[str, int] = defaultdict(int)
    commands_seen: list[str] = []

    for event in all_events:
        ip = event.get("client_ip")
        if ip:
            ip_counts[ip] += 1
        category_counts[classify_event(event)] += 1
        proto = event.get("protocol") or event.get("type") or "?"
        protocol_counts[proto] += 1
        cmd = _extract_command(event)
        if cmd:
            commands_seen.append(cmd)

    print(f"\n{'═'*70}")
    print(f"  SUMMARY")
    print(f"{'─'*70}")
    print(f"  Sessions : {len(sessions)}")
    print(f"  Events   : {total_events}")

    print(f"\n  Top IPs:")
    for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"    {ip:<20} {count} events")

    print(f"\n  Attack phases:")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        print(f"    {label(cat):<22} {count}")

    print(f"\n  Protocols:")
    for proto, count in sorted(protocol_counts.items(), key=lambda x: -x[1]):
        print(f"    {proto:<20} {count}")

    print(f"\n  Top commands:")
    from collections import Counter
    for cmd, count in Counter(commands_seen).most_common(10):
        print(f"    {count:>4}×  {cmd[:80]}")

    print(f"{'═'*70}\n")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Analyze HoneyMind attack logs")
    parser.add_argument("log_dir", nargs="?", default="/data/honeypot/logs",
                        help="Directory containing JSONL log files")
    parser.add_argument("--session", metavar="ID",
                        help="Show timeline for a specific session ID")
    parser.add_argument("--ip", metavar="IP",
                        help="Show all sessions from a given IP")
    parser.add_argument("--summary", action="store_true",
                        help="Show global summary only (no timelines)")
    args = parser.parse_args()

    log_dir = Path(args.log_dir)
    if not log_dir.exists():
        print(f"error: log directory not found: {log_dir}", file=sys.stderr)
        sys.exit(1)

    sessions = build_sessions(log_dir)
    if not sessions:
        print("no events found.")
        return

    if args.summary:
        print_summary(sessions)
        return

    if args.session:
        sid = args.session
        if sid not in sessions:
            print(f"session not found: {sid}", file=sys.stderr)
            sys.exit(1)
        print_session_timeline(sid, sessions[sid])
        return

    if args.ip:
        matched = {
            sid: events for sid, events in sessions.items()
            if any(e.get("client_ip") == args.ip for e in events)
        }
        if not matched:
            print(f"no sessions found for IP: {args.ip}", file=sys.stderr)
            sys.exit(1)
        for sid, events in matched.items():
            print_session_timeline(sid, events)
        print_summary({k: v for k, v in matched.items()})
        return

    # Default: print all timelines + summary
    for sid, events in sessions.items():
        print_session_timeline(sid, events)
    print_summary(sessions)


if __name__ == "__main__":
    main()
