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

from core.honeypot_utils import _load_env_file

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

_SYSTEM_PROMPT = """Tu es un expert en cybersécurité qui analyse des logs d'attaques honeypot.
Tu recevras des données de session compressées. Chaque session contient :
- IP, protocole, timing
- auth : résumé des tentatives d'authentification (nombre, mots de passe essayés, succès)
- commands : liste dédupliquée des commandes avec compteurs
- phases : phases d'attaque inspirées de MITRE ATT&CK
- files_accessed : fichiers lus par l'attaquant
- tools_detected : outils d'attaque identifiés

Ta mission :
1. Identifier ce que cherchait l'attaquant
2. Évaluer le niveau de sophistication (script kiddie / opportuniste / ciblé / APT)
3. Détecter si c'est une campagne coordonnée
4. Signaler les actions particulièrement dangereuses
5. Donner un résumé concis en 3-5 phrases

Sois concis. Concentre-toi sur ce qui est inhabituel ou dangereux. Évite les observations évidentes.
Réponds exclusivement en français."""

_SESSION_PROMPT = """Analyse cette session d'attaque :

{condensed}

Fournis :
- Ce que cherchait l'attaquant
- Niveau de sophistication
- Action la plus dangereuse
- Résumé en une phrase"""

_GLOBAL_PROMPT = """Analyse ces sessions d'attaques honeypot :

{condensed}

Fournis :
- Paysage global des menaces (ce que ciblent les attaquants)
- Signes de campagnes coordonnées
- Attaque la plus sophistiquée observée
- Actions défensives recommandées
- Résumé exécutif (3 phrases max)"""

_MULTIDIM_PROMPT = """Tu analyses une vue multidimensionnelle compressée de logs honeypot.

{condensed}

Dimensions couvertes :
- behavior : distribution bot/humain/agent IA + niveaux de sophistication
- technique : outils utilisés, phases d'attaque, protocoles, taux de succès
- network : campagnes détectées, pays, méthodes d'anonymisation
- temporal : patterns temporels, heures de pointe, attaques lentes vs rapides
- content : fichiers ciblés, commandes utilisées, pièges IA déclenchés

Fournis un rapport de threat intelligence concis :
1. Principaux acteurs malveillants et leurs objectifs
2. Campagne ou session la plus dangereuse
3. Patterns d'attaque et tendances
4. 2-3 recommandations défensives concrètes
5. Résumé exécutif (2 phrases)"""


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

def _call_llm(user_prompt: str, args=None, log_dir: Path = None) -> str:
    try:
        from llm_providers.llm_utils import invoke_llm
    except ImportError:
        return "[LLM not available — run with --dry-run to see condensed logs]"

    # Priority: CLI args > env vars > defaults
    model = (
        (args.model       if args else None)
        or os.environ.get("ANALYSIS_MODEL_ID")
        or os.environ.get("MODEL_ID")
        or "gpt-oss-20b"
    )
    provider = (
        (args.provider    if args else None)
        or os.environ.get("ANALYSIS_LLM_PROVIDER")
        or os.environ.get("LLM_PROVIDER")
    )
    base_url = (
        (args.base_url    if args else None)
        or os.environ.get("ANALYSIS_LLM_BASE_URL")
        or os.environ.get("LLM_BASE_URL")
    )
    api_key_env = (
        (args.api_key_env if args else None)
        or os.environ.get("ANALYSIS_LLM_API_KEY_ENV")
        or "LLM_API_KEY"
    )
    max_tokens = args.max_tokens if args else 600

    usage_db = (
        os.environ.get("LLM_USAGE_DB")
        or (str(log_dir / "llm_usage.db") if log_dir else None)
    )

    kwargs = {}
    if provider:
        kwargs["llm_provider"] = provider
    if base_url:
        kwargs["llm_base_url"] = base_url
    if api_key_env:
        kwargs["llm_api_key_env"] = api_key_env
    if usage_db:
        kwargs["llm_usage_db_path"] = usage_db

    print(f"  model: {model}  provider: {provider or 'auto'}  max_tokens: {max_tokens}")

    return invoke_llm(
        system_prompt=_SYSTEM_PROMPT,
        user_prompt=user_prompt,
        model_id=model,
        llm_max_tokens=max_tokens,
        **kwargs,
    )


# ── Helpers ──────────────────────────────────────────────────────────────────

def _resolve_env_file(env_file: str = None) -> None:
    """Load env file — explicit path > default locations."""
    candidates = []
    if env_file:
        candidates = [env_file]
    else:
        root = Path(__file__).resolve().parents[1]
        candidates = [
            root / "config" / "llm.env.list",
            root / "config" / ".env",
            Path(".env"),
            Path("config") / "llm.env.list",
        ]

    for path in candidates:
        p = Path(path)
        if p.exists():
            _load_env_file(str(p))
            print(f"  loaded env: {p}")
            return

    if env_file:
        print(f"warning: env file not found: {env_file}", file=sys.stderr)


def _sessions_for_campaign(campaign, sessions: dict) -> dict:
    """Return the subset of sessions belonging to a campaign, matched by IP."""
    campaign_ips = set(campaign.ips)
    result = {}
    for sid, events in sessions.items():
        for e in events:
            client = e.get("client") or {}
            ip = client.get("ip") or e.get("client_ip")
            if ip and ip in campaign_ips:
                result[sid] = events
                break
    return result


# ── Main ─────────────────────────────────────────────────────────────────────

_ALL_DIMENSIONS = ["behavior", "technique", "network", "temporal", "content"]


def main():
    parser = argparse.ArgumentParser(
        description="Analyze honeypot logs with LLM (token-efficient)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available dimensions: {', '.join(_ALL_DIMENSIONS)}",
    )
    parser.add_argument("log_dir", nargs="?", default="/data/honeypot/logs")
    parser.add_argument(
        "--env-file", metavar="FILE", default=None,
        help="Path to .env file with LLM config (default: config/llm.env.list or .env)",
    )
    parser.add_argument("--session", metavar="ID", help="Analyze a single session")
    parser.add_argument("--campaign", metavar="ID", help="Analyze a specific campaign (e.g. C001). Use --list-campaigns to see available ones")
    parser.add_argument("--list-campaigns", action="store_true", help="List detected campaigns and exit")
    parser.add_argument("--dry-run", action="store_true", help="Show condensed logs without calling LLM")
    parser.add_argument("--show-ratio", action="store_true", help="Show compression ratio stats")
    parser.add_argument("--top", type=int, default=10, help="Max sessions to analyze globally (default: 10)")
    parser.add_argument(
        "--by",
        nargs="+",
        metavar="DIM",
        choices=_ALL_DIMENSIONS,
        default=_ALL_DIMENSIONS,
        help=f"Dimensions to include. Choices: {', '.join(_ALL_DIMENSIONS)}",
    )

    llm = parser.add_argument_group("LLM configuration")
    llm.add_argument("--model",       default=None, help="Model ID (default: env MODEL_ID or gpt-oss-20b)")
    llm.add_argument("--provider",    default=None, help="LLM provider: ollama, openai_compatible, openai, anthropic, bedrock")
    llm.add_argument("--base-url",    default=None, help="LLM base URL (for openai_compatible / ollama)")
    llm.add_argument("--api-key-env", default=None, help="Env var name holding the API key (default: LLM_API_KEY)")
    llm.add_argument("--max-tokens",  type=int, default=600, help="Max tokens for LLM response (default: 600)")

    args = parser.parse_args()

    # Load .env file — CLI arg > default locations
    _resolve_env_file(args.env_file)

    log_dir = Path(args.log_dir)
    if not log_dir.exists():
        print(f"error: {log_dir} not found", file=sys.stderr)
        sys.exit(1)

    sessions = _load_sessions(log_dir)
    if not sessions:
        print("no events found.")
        return

    total_events = sum(len(e) for e in sessions.values())

    # Always compute campaigns (needed for --list-campaigns and --campaign)
    bot_human_results = {sid: analyze_bot_human(evts) for sid, evts in sessions.items()}
    campaigns = detect_campaigns(sessions)
    campaign_map = {c.campaign_id: c for c in campaigns}

    # List campaigns and exit
    if args.list_campaigns:
        if not campaigns:
            print("No campaigns detected.")
            return
        print(f"\n{'─'*60}")
        print(f"  {'ID':<8} {'Verdict':<22} {'Sessions':>8} {'IPs':>5} {'Conf':>6}")
        print(f"{'─'*60}")
        for c in campaigns:
            print(f"  {c.campaign_id:<8} {c.verdict:<22} {c.session_count:>8} {len(c.ips):>5} {int(c.confidence*100):>5}%")
            if c.shared_commands:
                tools = [x for x in c.shared_commands if x.startswith("[")]
                cmds  = [x for x in c.shared_commands if not x.startswith("[")][:3]
                if tools:
                    print(f"           tool: {tools[0]}")
                if cmds:
                    print(f"           shared: {', '.join(cmds)}")
        print(f"{'─'*60}")
        return

    # Campaign analysis
    if args.campaign:
        cid = args.campaign.upper()
        if cid not in campaign_map:
            available = ", ".join(campaign_map.keys()) or "none detected"
            print(f"Campaign '{cid}' not found. Available: {available}", file=sys.stderr)
            sys.exit(1)

        campaign = campaign_map[cid]
        # Resolve session IDs belonging to this campaign
        campaign_sessions = _sessions_for_campaign(campaign, sessions)

        if not campaign_sessions:
            print(f"No sessions found for campaign {cid}", file=sys.stderr)
            sys.exit(1)

        bh_for_campaign = {sid: bot_human_results[sid] for sid in campaign_sessions if sid in bot_human_results}

        attacker_profiles = {}
        from analysis.attack_classifier import classify_event
        for sid, evts in campaign_sessions.items():
            bh = bh_for_campaign.get(sid)
            if bh:
                cats = {classify_event(e) for e in evts}
                attacker_profiles[sid] = build_profile({}, bh, cats)

        full = condense_multidimensional(
            campaign_sessions,
            bot_human_results=bh_for_campaign,
            campaigns=[campaign],
            attacker_profiles=attacker_profiles,
        )
        full["campaign"] = {
            "id":       campaign.campaign_id,
            "verdict":  campaign.verdict,
            "sessions": campaign.session_count,
            "ips":      campaign.ips,
            "window":   f"{(campaign.time_start or '')[:16]} → {(campaign.time_end or '')[:16]}",
            "shared_commands": campaign.shared_commands[:10],
            "confidence": f"{int(campaign.confidence * 100)}%",
        }

        condensed_global = {"meta": full["meta"], "campaign": full["campaign"]}
        for dim in args.by:
            if dim in full:
                condensed_global[dim] = full[dim]

        condensed_str = json.dumps(condensed_global, indent=2, ensure_ascii=False)
        n_events = sum(len(e) for e in campaign_sessions.values())
        print(f"\n── Campaign {cid} — {len(campaign_sessions)} sessions, {n_events} events ──")
        print(condensed_str)

        if args.show_ratio:
            print(f"\n── Compression: {compression_ratio(n_events, condensed_str)} ──")

        if not args.dry_run:
            prompt = _MULTIDIM_PROMPT.format(condensed=condensed_str)
            print(f"\n── LLM Analysis (campaign {cid}) ──")
            print(_call_llm(prompt, args, log_dir))
        return

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
            result = _call_llm(_SESSION_PROMPT.format(condensed=condensed_str), args, log_dir)
            print(result)
        return

    # Compute attacker profiles (bot_human_results + campaigns already computed above)
    from analysis.attack_classifier import classify_event
    attacker_profiles = {}
    for sid, evts in sessions.items():
        bh = bot_human_results[sid]
        cats = {classify_event(e) for e in evts}
        attacker_profiles[sid] = build_profile({}, bh, cats)

    # Build multidimensional condensed view
    full = condense_multidimensional(
        sessions,
        bot_human_results=bot_human_results,
        campaigns=campaigns,
        attacker_profiles=attacker_profiles,
    )

    # Filter to selected dimensions only
    condensed_global = {"meta": full["meta"]}
    for dim in args.by:
        if dim in full:
            condensed_global[dim] = full[dim]

    condensed_str = json.dumps(condensed_global, indent=2, ensure_ascii=False)
    dims_label = ", ".join(args.by)

    print(f"\n── Condensed [{dims_label}] ({len(sessions)} sessions, {total_events} events) ──")
    print(condensed_str)

    if args.show_ratio:
        print(f"\n── Compression: {compression_ratio(total_events, condensed_str)} ──")

    if not args.dry_run:
        print(f"\n── LLM Analysis ──")
        result = _call_llm(_MULTIDIM_PROMPT.format(condensed=condensed_str), args, log_dir)
        print(result)


if __name__ == "__main__":
    main()
