#!/usr/bin/env python3
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from infra.data_handler import DataHandler


def _load_config(folder: str) -> dict:
    config_path = os.path.join(folder, "config.json")
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"config.json not found in {folder}")
    with open(config_path) as f:
        config = json.load(f)
    config["data_file"] = os.path.join(folder, "data.jsonl")
    return config


def _parse_terms(terms: list) -> dict:
    result = {}
    for term in terms:
        if "=" not in term:
            raise ValueError(f"Invalid term '{term}': expected key=value")
        key, _, value = term.partition("=")
        result[key.strip()] = value.strip()
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Remove a cached response from a honeypot data store"
    )
    parser.add_argument("folder", help="Honeypot folder (must contain config.json)")
    parser.add_argument(
        "terms",
        nargs="*",
        metavar="key=value",
        help="Search terms, e.g. command=whoami or path=/login args=?user=admin",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Remove all dynamic (LLM-generated) entries, keeping static data.jsonl entries",
    )
    args = parser.parse_args()

    if not args.all and not args.terms:
        parser.error("provide search terms or use --all to clear the entire dynamic cache")

    config = _load_config(args.folder)
    handler = DataHandler(
        data_file=str(config["data_file"]),
        system_prompt=config.get("system_prompt", ""),
        model_id=config.get("model_id", ""),
    )

    if args.all:
        count = handler._data_store.clear()
        print(f"cleared {count} dynamic entries")
        return

    try:
        search_terms = _parse_terms(args.terms)
    except ValueError as e:
        parser.error(str(e))

    removed = handler.remove(search_terms)
    if removed:
        print(f"removed: {search_terms}")
    else:
        print(f"not found: {search_terms}")
        sys.exit(1)


if __name__ == "__main__":
    main()
