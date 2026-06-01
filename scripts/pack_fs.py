#!/usr/bin/env python3
"""
Pack an editable JSONL filesystem file into JSONL.GZ for HoneyMind.

Usage:
    python scripts/pack_fs.py my_fs.jsonl
    # → produces my_fs.jsonl.gz, ready to reference in config.json as "fs_file"
"""
import argparse
import gzip
import json
from pathlib import Path


def _enrich(entry: dict) -> dict:
    path = entry["path"]
    result = dict(entry)
    result.setdefault("parent_path", str(Path(path).parent) if path != "/" else None)
    result.setdefault("name", Path(path).name if path != "/" else "")
    content = result.get("content", "")
    result.setdefault("size", len(content.encode()) if content else 0)
    result.setdefault("modified_at", None)
    return result


def main():
    parser = argparse.ArgumentParser(description="Pack a JSONL filesystem into JSONL.GZ for HoneyMind")
    parser.add_argument("input", help="Input JSONL file")
    parser.add_argument("-o", "--output", help="Output path (default: <input>.gz)")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        parser.error(f"file not found: {input_path}")

    output_path = Path(args.output) if args.output else Path(str(input_path) + ".gz")

    count = 0
    with open(input_path, encoding="utf-8") as f_in, \
         gzip.open(output_path, "wt", encoding="utf-8") as f_out:
        for i, line in enumerate(f_in, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"warning: line {i} is invalid JSON, skipping ({e})")
                continue
            if "path" not in entry:
                print(f"warning: line {i} missing 'path', skipping")
                continue
            f_out.write(json.dumps(_enrich(entry), ensure_ascii=False) + "\n")
            count += 1

    print(f"packed {count} entries → {output_path}")
    print(f"set in config.json: \"fs_file\": \"{output_path}\"")


if __name__ == "__main__":
    main()
