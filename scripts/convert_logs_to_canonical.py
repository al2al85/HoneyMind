#!/usr/bin/env python3
"""Convert legacy HoneyMind/dd-honeypot JSONL logs to canonical events."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from canonical_log_utils import convert_legacy_event
from local_log_utils import event_to_json


def iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as f:
        for line_number, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"Skipping malformed JSON at {path}:{line_number}: {exc}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert legacy HoneyMind logs")
    parser.add_argument("input", help="Legacy JSONL log file")
    parser.add_argument("output", help="Canonical JSONL output file")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as out:
        for event in iter_jsonl(input_path):
            out.write(event_to_json(convert_legacy_event(event)))
            out.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
