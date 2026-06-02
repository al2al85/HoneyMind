#!/usr/bin/env python3
"""
Analyze condensed HoneyMind logs with an LLM.

The logs are compressed before sending to minimize token usage:
- Repeated commands are deduplicated with counts
- Auth attempts are summarized
- Only unique information is kept

Usage:
    python scripts/analyze_with_llm.py [log_dir]
    python scripts/analyze_with_llm.py [log_dir] --session <id>
    python scripts/analyze_with_llm.py [log_dir] --dry-run   # show condensed logs, no LLM call
    python scripts/analyze_with_llm.py [log_dir] --show-ratio # show compression stats
"""
import argparse
import gzip
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from analysis.log_condenser import (
    condense_session,
    condense_sessions,
    condense_multidimensional,
    compression_ratio,
    estimate_tokens,
)
from analysis.bot_human_analyzer import analyze as analyze_bot_human
from analysis.campaign_detector import detect_campaigns
from analysis.attacker_profiler import profile as build_profile

_SYSTEM_PROMPT = """You are a cybersecurity expert analyzing honeypot attack logs.
You will receive compressed session data. Each session contains:
- IP, protocol, timing
- auth: authentication attempts summary (count, passwords tried, success)
- commands: deduplicated list of commands with counts
- phases: MITRE ATT&CK-inspired attack phases observed
- files_accessed: files the attacker read
- tools_detected: known attack tools identified

Your task:
1. Identify what the attacker was looking for
2. Assess sophistication level (script kiddie / opportunist / targeted / APT)
3. Detect if this is part of a coordinated campaign
4. Flag any particularly dangerous actions
5. Give a concise summary in 3-5 sentences

Be concise. Focus on what's unusual or dangerous. Skip obvious observations."""

_SESSION_PROMPT = """Analyze this attack session:

{condensed}

Provide:
- What the attacker was looking for
- Sophistication level
- Most dangerous action
- One-sentence summary"""

_GLOBAL_PROMPT = """Analyze these honeypot attack sessions:

{condensed}

Provide:
- Overall threat landscape (what attackers are targeting)
- Signs of coordinated campaigns
- Most sophisticated attack observed
- Recommended defensive actions
- Executive summary (3 sentences max)"""

_MULTIDIM_PROMPT = """You are analyzing a compressed multidimensional view of honeypot logs.

{condensed}

Dimensions covered:
- behavior: bot/human/AI agent distribution + sophistication levels
- technique: tools used, attack phases, protocols, success rates
- network: campaigns detected, countries, anonymization methods
- temporal: timing patterns, peak hours, slow vs fast attacks
- content: files targeted, commands used, AI traps triggered

Provide a concise threat intelligence report:
1. Main threat actors and their objectives
2. Most dangerous campaign or session
3. Attack patterns and trends
4. 2-3 concrete defensive recommendations
5. Executive summary (2 sentences)"""


# ── Log loading ───────────────────────────────────────────────────────────────

def _open(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open("r", encoding="utf-8")


def _load_sessions(log_dir: Path) -> dict[str, list[dict]]:
    sessions = defaultdict(list)
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
                if event.get("schema_version") == 1 or event.get("dd-honeypot"):
                    sid = event.get("session_id") or event.get("session-id") or "unknown"
                    sessions[sid].append(event)
    for sid in sessions:
        sessions[sid].sort(key=lambda e: (e.get("seq") or 0, e.get("timestamp") or e.get("time") or ""))
    return dict(sessions)


# ── LLM call ─────────────────────────────────────────────────────────────────

def _call_llm(user_prompt: str) -> str:
    try:
        from llm_providers.llm_utils import invoke_llm
    except ImportError:
        return "[LLM not available — run with --dry-run to see condensed logs]"

    model = os.environ.get("ANALYSIS_MODEL_ID") or os.environ.get("MODEL_ID") or "gpt-oss-20b"
    provider = os.environ.get("ANALYSIS_LLM_PROVIDER") or os.environ.get("LLM_PROVIDER")
    base_url = os.environ.get("ANALYSIS_LLM_BASE_URL") or os.environ.get("LLM_BASE_URL")
    api_key_env = os.environ.get("ANALYSIS_LLM_API_KEY_ENV") or "LLM_API_KEY"

    kwargs = {}
    if provider:
        kwargs["llm_provider"] = provider
    if base_url:
        kwargs["llm_base_url"] = base_url
    if api_key_env:
        kwargs["llm_api_key_env"] = api_key_env

    return invoke_llm(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        model_id=model,
        llm_max_tokens=600,
        **kwargs,
    )


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Analyze honeypot logs with LLM (token-efficient)")
    parser.add_argument("log_dir", nargs="?", default="/data/honeypot/logs")
    parser.add_argument("--session", metavar="ID", help="Analyze a single session")
    parser.add_argument("--dry-run", action="store_true", help="Show condensed logs without calling LLM")
    parser.add_argument("--show-ratio", action="store_true", help="Show compression ratio stats")
    parser.add_argument("--top", type=int, default=10, help="Max sessions to analyze globally (default: 10)")
    args = parser.parse_args()

    log_dir = Path(args.log_dir)
    if not log_dir.exists():
        print(f"error: {log_dir} not found", file=sys.stderr)
        sys.exit(1)

    sessions = _load_sessions(log_dir)
    if not sessions:
        print("no events found.")
        return

    total_events = sum(len(e) for e in sessions.values())

    # Single session analysis
    if args.session:
        if args.session not in sessions:
            print(f"session not found: {args.session}", file=sys.stderr)
            sys.exit(1)

        condensed = condense_session(sessions[args.session])
        condensed_str = json.dumps(condensed, indent=2, ensure_ascii=False)

        print(f"\n── Condensed session ({args.session[:8]}...) ──")
        print(condensed_str)

        if args.show_ratio:
            print(f"\n── Compression: {compression_ratio(len(sessions[args.session]), condensed_str)} ──")

        if not args.dry_run:
            print(f"\n── LLM Analysis ──")
            result = _call_llm(_SESSION_PROMPT.format(condensed=condensed_str))
            print(result)
        return

    # Compute analysis results for all sessions
    bot_human_results = {sid: analyze_bot_human(evts) for sid, evts in sessions.items()}
    campaigns = detect_campaigns(sessions)

    attacker_profiles = {}
    for sid, evts in sessions.items():
        bh = bot_human_results[sid]
        from analysis.attack_classifier import classify_event
        cats = {classify_event(e) for e in evts}
        attacker_profiles[sid] = build_profile({}, bh, cats)

    # Build multidimensional condensed view
    condensed_global = condense_multidimensional(
        sessions,
        bot_human_results=bot_human_results,
        campaigns=campaigns,
        attacker_profiles=attacker_profiles,
    )
    condensed_str = json.dumps(condensed_global, indent=2, ensure_ascii=False)

    print(f"\n── Multidimensional condensed view ({len(sessions)} sessions, {total_events} events) ──")
    print(condensed_str)

    if args.show_ratio:
        print(f"\n── Compression: {compression_ratio(total_events, condensed_str)} ──")

    if not args.dry_run:
        print(f"\n── LLM Analysis ──")
        result = _call_llm(_MULTIDIM_PROMPT.format(condensed=condensed_str))
        print(result)


if __name__ == "__main__":
    main()
