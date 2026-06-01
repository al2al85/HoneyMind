#!/usr/bin/env python3
import argparse
import gzip
import json
from collections import Counter, defaultdict
from pathlib import Path


def _open_log(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open("r", encoding="utf-8")


def _iter_events(log_dir: Path):
    for path in sorted(log_dir.glob("*.jsonl")) + sorted(log_dir.glob("*.jsonl.gz")):
        with _open_log(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("dd-honeypot") is True:
                    yield event


def _client_ip(event: dict):
    login = event.get("login") or {}
    if isinstance(login, dict) and login.get("client_ip"):
        return login["client_ip"]
    http_request = event.get("http-request") or {}
    if isinstance(http_request, dict):
        return http_request.get("client_ip")
    return None


def _event_command(event: dict):
    if event.get("command"):
        return event["command"]
    if event.get("query"):
        return event["query"]
    http_request = event.get("http-request") or {}
    if isinstance(http_request, dict) and http_request.get("path") is not None:
        method = http_request.get("method", "GET")
        path = http_request.get("path", "")
        return f"{method} /{path}".rstrip("/")
    return None


def summarize(log_dir: Path):
    sessions = defaultdict(list)
    source_ips = Counter()
    protocols = Counter()
    commands = Counter()

    for event in _iter_events(log_dir):
        sessions[event.get("session-id") or "unknown"].append(event)
        if event.get("type"):
            protocols[event["type"]] += 1
        ip = _client_ip(event)
        if ip:
            source_ips[ip] += 1
        command = _event_command(event)
        if command:
            commands[command] += 1

    event_count = sum(len(events) for events in sessions.values())
    print(f"sessions: {len(sessions)}")
    print(f"events: {event_count}")
    print("source_ips:")
    for ip, count in source_ips.most_common(10):
        print(f"  {ip}: {count}")
    print("protocols:")
    for protocol, count in protocols.most_common():
        print(f"  {protocol}: {count}")
    print("top_commands:")
    for command, count in commands.most_common(10):
        print(f"  {command}: {count}")


def main():
    parser = argparse.ArgumentParser(description="Summarize local HoneyMind JSONL logs")
    parser.add_argument("log_dir", nargs="?", default="/data/honeypot/logs")
    args = parser.parse_args()
    summarize(Path(args.log_dir))


if __name__ == "__main__":
    main()
