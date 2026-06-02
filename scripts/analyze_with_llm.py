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

# ── System prompts ────────────────────────────────────────────────────────────
# Deep : analyse complète session / campagne
# Overview : synthèse globale multi-sessions

_SYSTEM_PROMPT_DEEP = """Tu es un analyste cybersécurité spécialisé dans la télémétrie honeypot, le profilage d'attaquants et la corrélation de campagnes.

Règles absolues :
- Ne jamais inventer d'informations. Si une donnée est absente : "inconnu" ou "non observé".
- Toute hypothèse doit être explicitement marquée avec un niveau de confiance (faible / moyen / élevé).
- Chaque conclusion doit citer la preuve issue des logs.
- Pas d'attribution formelle sans preuve forte.
- Sortie en français, format markdown."""

_SYSTEM_PROMPT_OVERVIEW = """Tu es un analyste cybersécurité. Tu reçois une vue agrégée de logs honeypot couvrant plusieurs sessions et campagnes.
Produis une synthèse de threat intelligence en français, format markdown. Sois synthétique. Ne jamais inventer."""


# ── User prompts ──────────────────────────────────────────────────────────────

_SESSION_PROMPT = """Analyse cette session d'attaque :

{condensed}

Produis un rapport structuré couvrant :
1. **Phases de l'attaque** — classifier chaque phase observée (recon, accès initial, exécution, persistance, privesc, latéral, exfiltration, dépôt de fichiers)
2. **Chemin d'attaque** — timeline chronologique + séquence logique des actions
3. **Outils identifiés** — commandes natives, outils de téléchargement, malware, scanners
4. **Type d'agent** — bot / humain / semi-automatisé, avec justification comportementale
5. **Profil attaquant** — IP, pays, ASN, FAI, anonymisation (VPN/Tor/datacenter/résidentiel)
6. **Objectif probable** — avec niveau de confiance
7. **Interaction honeypot** — a-t-il cru à l'environnement ? faux fichiers consultés ?
8. **Score de sophistication** — 0-100, justification, niveau (très faible → très élevé)
9. **Mapping MITRE ATT&CK** — uniquement un diagramme Mermaid"""

_CAMPAIGN_PROMPT = """Analyse cette campagne d'attaque :

{condensed}

Produis un rapport structuré couvrant :
1. **Phases de l'attaque** — phases observées sur l'ensemble des sessions de la campagne
2. **Chemin d'attaque** — timeline et séquence logique commune aux sessions
3. **Outils identifiés** — outils partagés entre sessions, infrastructure commune
4. **Type d'agent** — bot / humain / semi-automatisé, cohérence inter-sessions
5. **Profil attaquant** — IPs impliquées, pays, ASN, anonymisation, corrélations
6. **Objectif probable** — avec niveau de confiance
7. **Interaction honeypot** — réactions aux leurres, signes de détection du honeypot
8. **Score de sophistication** — 0-100, justification, niveau (très faible → très élevé)
9. **Mapping MITRE ATT&CK** — uniquement un diagramme Mermaid"""

_GLOBAL_PROMPT = """Vue agrégée des sessions honeypot :

{condensed}

Produis une synthèse threat intelligence :
1. **Paysage des menaces** — qui attaque, quels objectifs, quels patterns dominants
2. **Campagne la plus dangereuse** — pourquoi, indicateurs clés
3. **Tendances** — outils, techniques, timing, évolution
4. **Recommandations défensives** — 3 actions prioritaires et concrètes
5. **Résumé exécutif** — 2-3 phrases"""


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

def _call_llm(user_prompt: str, args=None, log_dir: Path = None, system_prompt: str = None) -> str:
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
    max_tokens = (
        (args.max_tokens if args else None)
        or int(os.environ.get("ANALYSIS_LLM_MAX_TOKENS") or os.environ.get("LLM_MAX_TOKENS") or 600)
    )

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
        system_prompt=system_prompt or _SYSTEM_PROMPT_DEEP,
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


def _build_ip_cache(sessions: dict, log_dir: Path) -> dict:
    """Enrich all unique attacker IPs (geoloc, ASN, proxy) with SQLite cache."""
    from analysis.ip_enricher import IPEnricher

    ips = set()
    for events in sessions.values():
        for e in events:
            ip = (e.get("client") or {}).get("ip") or e.get("client_ip")
            if ip:
                ips.add(ip)
                break

    if not ips:
        return {}

    cache_path = str(log_dir / "ip_cache.db")
    enricher = IPEnricher(cache_path=cache_path)
    result = {}
    for ip in ips:
        try:
            result[ip] = enricher.enrich(ip)
        except Exception:
            pass
    return result


def _build_session_timeline(sessions: dict, max_per_session: int = 20, cmd_max_len: int = 120) -> dict:
    """
    Compact per-session command timeline for LLM context.
    Format: ["HH:MM:SS CAT: cmd..."] — deduped, truncated, one string per entry.
    """
    from analysis.attack_classifier import classify_command

    timeline = {}
    for sid, events in sessions.items():
        entries = []
        seen = set()
        for e in events:
            cmd = e.get("command")
            if isinstance(cmd, dict):
                raw = cmd.get("raw") or cmd.get("normalized")
            elif isinstance(cmd, str):
                raw = cmd
            else:
                continue
            if not raw:
                continue
            # Deduplicate within session
            key = raw[:60]
            if key in seen:
                continue
            seen.add(key)

            ts = (e.get("timestamp") or e.get("time") or "")[11:19]  # HH:MM:SS only
            cat = classify_command(raw).value
            truncated = raw[:cmd_max_len] + ("…" if len(raw) > cmd_max_len else "")
            entries.append(f"{ts} {cat}: {truncated}")

        if entries:
            timeline[sid[:8]] = entries[:max_per_session]
    return timeline


def _session_ip_map(sessions: dict) -> dict:
    """Returns {session_id: ip}."""
    result = {}
    for sid, events in sessions.items():
        for e in events:
            ip = (e.get("client") or {}).get("ip") or e.get("client_ip")
            if ip:
                result[sid] = ip
                break
    return result


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
    llm.add_argument("--max-tokens",  type=int, default=None, help="Max tokens for LLM response (default: env LLM_MAX_TOKENS or 600)")

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
    ip_cache = _build_ip_cache(sessions, log_dir)
    sid_to_ip = _session_ip_map(sessions)

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
                ip_data = ip_cache.get(sid_to_ip.get(sid), {})
                attacker_profiles[sid] = build_profile(ip_data, bh, cats)

        full = condense_multidimensional(
            campaign_sessions,
            bot_human_results=bh_for_campaign,
            ip_cache=ip_cache,
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
        condensed_global["timeline"] = _build_session_timeline(campaign_sessions)

        condensed_str = json.dumps(condensed_global, indent=2, ensure_ascii=False)
        n_events = sum(len(e) for e in campaign_sessions.values())
        print(f"\n── Campaign {cid} — {len(campaign_sessions)} sessions, {n_events} events ──")
        print(condensed_str)

        if args.show_ratio:
            print(f"\n── Compression: {compression_ratio(n_events, condensed_str)} ──")

        if not args.dry_run:
            print(f"\n── LLM Analysis (campaign {cid}) ──")
            print(_call_llm(
                _CAMPAIGN_PROMPT.format(condensed=condensed_str),
                args, log_dir,
                system_prompt=_SYSTEM_PROMPT_DEEP,
            ))
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
            print(_call_llm(
                _SESSION_PROMPT.format(condensed=condensed_str),
                args, log_dir,
                system_prompt=_SYSTEM_PROMPT_DEEP,
            ))
        return

    # Compute attacker profiles (bot_human_results + campaigns already computed above)
    from analysis.attack_classifier import classify_event
    attacker_profiles = {}
    for sid, evts in sessions.items():
        bh = bot_human_results[sid]
        cats = {classify_event(e) for e in evts}
        ip_data = ip_cache.get(sid_to_ip.get(sid), {})
        attacker_profiles[sid] = build_profile(ip_data, bh, cats)

    # Build multidimensional condensed view
    full = condense_multidimensional(
        sessions,
        bot_human_results=bot_human_results,
        ip_cache=ip_cache,
        campaigns=campaigns,
        attacker_profiles=attacker_profiles,
    )

    # Filter to selected dimensions only
    top_sessions = dict(
        sorted(sessions.items(), key=lambda kv: len(kv[1]), reverse=True)[:args.top]
    )
    condensed_global = {"meta": full["meta"]}
    for dim in args.by:
        if dim in full:
            condensed_global[dim] = full[dim]
    condensed_global["timeline"] = _build_session_timeline(top_sessions)

    condensed_str = json.dumps(condensed_global, indent=2, ensure_ascii=False)
    dims_label = ", ".join(args.by)

    print(f"\n── Condensed [{dims_label}] ({len(sessions)} sessions, {total_events} events) ──")
    print(condensed_str)

    if args.show_ratio:
        print(f"\n── Compression: {compression_ratio(total_events, condensed_str)} ──")

    if not args.dry_run:
        print(f"\n── LLM Analysis ──")
        print(_call_llm(
            _GLOBAL_PROMPT.format(condensed=condensed_str),
            args, log_dir,
            system_prompt=_SYSTEM_PROMPT_OVERVIEW,
        ))


if __name__ == "__main__":
    main()
