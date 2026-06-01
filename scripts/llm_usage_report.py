#!/usr/bin/env python3
"""Print LLM usage summaries from a HoneyMind SQLite usage database.

Examples:
    python scripts/llm_usage_report.py /data/honeypot/logs/llm_usage.db
    python scripts/llm_usage_report.py /data/honeypot/logs/llm_usage.db --daily
    python scripts/llm_usage_report.py /data/honeypot/logs/llm_usage.db --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from llm_usage import get_daily_usage_summary, get_usage_summary, iter_usage_rows


def _format_table(rows: list[dict], columns: list[str]) -> str:
    if not rows:
        return "(no rows)"

    widths = {col: len(col) for col in columns}
    for row in rows:
        for col in columns:
            widths[col] = max(widths[col], len(str(row.get(col, ""))))

    header = "  ".join(col.ljust(widths[col]) for col in columns)
    separator = "  ".join("-" * widths[col] for col in columns)
    lines = [header, separator]
    for row in rows:
        lines.append("  ".join(str(row.get(col, "")).ljust(widths[col]) for col in columns))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Report HoneyMind LLM usage")
    parser.add_argument("db_path", help="Path to llm_usage.db")
    parser.add_argument("--daily", action="store_true", help="Group by day")
    parser.add_argument("--rows", action="store_true", help="Print raw rows instead of summaries")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()

    if args.rows:
        rows = iter_usage_rows(args.db_path)
        if args.json:
            print(json.dumps(rows, indent=2, ensure_ascii=False, default=str))
        else:
            print(_format_table(
                rows,
                [
                    "created_at",
                    "provider",
                    "model_id",
                    "prompt_tokens",
                    "completion_tokens",
                    "total_tokens",
                    "total_cost_usd",
                    "currency",
                ],
            ))
        return 0

    rows = get_daily_usage_summary(args.db_path) if args.daily else get_usage_summary(args.db_path)
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False, default=str))
        return 0

    if args.daily:
        columns = [
            "day",
            "provider",
            "model_id",
            "calls",
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "total_cost_usd",
            "currency",
        ]
    else:
        columns = [
            "provider",
            "model_id",
            "calls",
            "prompt_tokens",
            "completion_tokens",
            "total_tokens",
            "total_cost_usd",
            "currency",
        ]
    print(_format_table(rows, columns))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())