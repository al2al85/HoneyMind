"""Enrich canonical HoneyMind events with attack intel — uses src/ modules from main."""
import re
import sys
import os
from typing import Any, Optional
from collections import defaultdict

# In Docker, src is mounted at /honeymind_src (docker-compose volume).
# In dev, it sits at ../../src relative to this file.
_here = os.path.dirname(os.path.abspath(__file__))
for _src in ["/honeymind_src", os.path.abspath(os.path.join(_here, "..", "..", "src"))]:
    if os.path.isdir(_src):
        sys.path.insert(0, _src)
        sys.path.insert(0, os.path.join(_src, "analysis"))
        sys.path.insert(0, os.path.join(_src, "logging_pipeline"))

from attack_classifier import classify_event, Category
from ip_enricher import IPEnricher
from bot_human_analyzer import analyze as bh_analyze, BotHumanResult
from session_fingerprint import fingerprint_session, compute_sequence_hash
from attacker_profiler import profile as build_profile
from ai_traps import detect_traps
from detectors.tools import detect_tools, detect_anonymization, detect_uploaded_file
from detectors.sophistication import detect_obfuscation

_ip_enricher = IPEnricher(cache_path="/tmp/honeymind_ip_cache.db")

# Per-session accumulators
_session_events: dict[str, list[dict]] = defaultdict(list)
_session_phases: dict[str, list[str]] = defaultdict(list)


def _extract_command(event: dict) -> Optional[str]:
    cmd = event.get("command")
    if isinstance(cmd, dict):
        return cmd.get("raw") or cmd.get("normalized")
    if isinstance(cmd, str):
        return cmd
    if event.get("query"):
        return str(event["query"])
    http = event.get("http-request") or {}
    if isinstance(http, dict) and http.get("path") is not None:
        return f"{http.get('method','GET')} /{http.get('path','')}"
    return None


def _extract_client_ip(event: dict) -> str:
    client = event.get("client") or {}
    if isinstance(client, dict):
        return client.get("ip") or ""
    return event.get("client_ip") or ""


def _extract_username(event: dict) -> str:
    client = event.get("client") or {}
    if isinstance(client, dict):
        return client.get("username") or ""
    auth = event.get("auth") or {}
    return auth.get("username") or event.get("username") or ""


_FILE_ACCESS_PATTERN = re.compile(
    r"(?:cat|less|more|head|tail|vi|nano|vim)\s+(/\S+)", re.I
)

# Énergie estimée par 1000 tokens de *completion* (Wh/ktok).
#
# Méthodologie :
#   - Tokens de completion (décodage autorégressif, séquentiel) : taux de base
#   - Tokens de prompt (prefill parallèle) : ~4× moins coûteux → pondérés à 0.25
#   - Sources : IEA 2024 (~3 Wh/requête ChatGPT), benchmarks A100 batchés,
#     estimations MLCommons inférence LLM en production (1–3 Wh/ktok)
#   - Ollama/local : plus élevé, pas de batching, GPU grand public
_WH_PER_KTOK = {
    "anthropic":         1.5,   # cloud, inference batché et optimisé
    "openai":            1.5,   # idem
    "bedrock":           1.5,   # AWS-hosted
    "ollama":            3.0,   # GPU local, pas de batching
    "openai_compatible": 2.0,   # fournisseur inconnu, valeur prudente
}
# Intensité carbone : moyenne mondiale IEA 2022 = 460 gCO2/kWh = 0.46 gCO2/Wh
_GRID_GCO2_PER_WH = 0.46


def _co2_estimate(prompt_tokens: int, completion_tokens: int, provider: str) -> tuple[float, float]:
    # Prompt (prefill parallèle) ≈ 4× moins coûteux que completion (décodage séquentiel)
    effective_tokens = prompt_tokens * 0.25 + completion_tokens
    rate_wh_per_ktok = _WH_PER_KTOK.get(provider, 2.0)
    energy_wh = (effective_tokens / 1000) * rate_wh_per_ktok
    co2_g = energy_wh * _GRID_GCO2_PER_WH
    return round(co2_g, 6), round(energy_wh, 6)


def enrich(event: dict) -> dict:
    e = dict(event)
    sid = e.get("session_id") or "unknown"
    ip = _extract_client_ip(e)
    command = _extract_command(e)
    event_type = e.get("event_type", "")

    # Accumulate session events for multi-event analysis
    _session_events[sid].append(e)

    # --- Attack classification ---
    category: Category = classify_event(e)
    e["_attack_category"] = category.value
    if category.value not in _session_phases[sid]:
        _session_phases[sid].append(category.value)

    # --- Backfill command_raw at top-level for Loki/Grafana queries ---
    if "command_raw" not in e:
        cmd_obj = e.get("command")
        if isinstance(cmd_obj, dict) and cmd_obj.get("raw"):
            e["command_raw"] = cmd_obj["raw"]

    # --- GeoIP + anonymization (using src/ip_enricher.py) ---
    geo = _ip_enricher.enrich(ip) if ip else {}
    e["_geo"] = geo

    # --- Tool detection ---
    tools_found: list[str] = []
    anonymization: list[str] = []
    uploaded_file: Optional[str] = None
    obfuscated = False
    if command:
        tools_found = detect_tools(command)
        anonymization = detect_anonymization(command)
        uploaded_file = detect_uploaded_file(command)
        obfuscated = detect_obfuscation(command)
    e["_tools"] = tools_found
    e["_anonymization"] = anonymization
    e["_uploaded_file"] = uploaded_file
    e["_obfuscated"] = obfuscated

    # --- Bot/Human analysis (using src/bot_human_analyzer.py) ---
    session_events = _session_events[sid]
    bh: BotHumanResult = bh_analyze(session_events)
    e["_bot"] = {
        "verdict": bh.verdict,
        "confidence": bh.confidence,
        "signals": bh.signals,
        "ai_trap_hits": len(bh.ai_trap_hits),
        "ai_trap_details": [
            {"trap_id": h.trap_id, "command": h.command, "confidence": h.confidence}
            for h in bh.ai_trap_hits
        ],
    }

    # --- AI trap check on current command ---
    if command:
        current_traps = detect_traps([command])
        e["_ai_trap_triggered"] = len(current_traps) > 0
        e["_ai_trap_ids"] = [t.trap_id for t in current_traps]
    else:
        e["_ai_trap_triggered"] = False
        e["_ai_trap_ids"] = []

    # --- SSH HASSH (from event if logged by ssh_honeypot) ---
    # ssh_fingerprint can be top-level or nested in details (emitted as event_type="error")
    ssh_fp = e.get("ssh_fingerprint") or (e.get("details") or {}).get("ssh_fingerprint") or {}

    # --- Session fingerprint ---
    fp = fingerprint_session(session_events, hassh=ssh_fp.get("hassh"))
    e["_fingerprint"] = fp

    e["_hassh"] = ssh_fp.get("hassh") or ""
    e["_ssh_client"] = ssh_fp.get("client_name") or ssh_fp.get("client_banner") or fp.get("ua_tool") or ""
    e["_tool_match"] = fp.get("tool_match") or ""

    # --- Attacker profile (using src/attacker_profiler.py) ---
    prof = build_profile(
        ip_data=geo,
        bh_result=bh,
        categories={category},
        local_hour=_ip_enricher.local_hour(geo, __import__("datetime").datetime.utcnow().hour) if geo else None,
    )
    e["_profile"] = prof
    e["_sophistication"] = prof["profile_type"]   # script_kiddie / opportunist / targeted / nation_state
    e["_sophistication_score"] = prof["sophistication_score"]
    e["_profile_label"] = prof["profile_label"]
    e["_profile_flags"] = prof.get("flags", [])
    e["_narrative"] = prof.get("narrative", "")

    # --- File access extraction ---
    if command:
        fm = _FILE_ACCESS_PATTERN.search(command)
        e["_file_accessed"] = fm.group(1) if fm else None
    else:
        e["_file_accessed"] = None

    # --- Auth fields ---
    auth = e.get("auth") or {}
    e["_auth_success"] = str(auth.get("success", "")).lower() if auth else ""
    e["_auth_username"] = _extract_username(e)
    e["_auth_password"] = auth.get("password", "") if auth else ""

    # --- LLM ecology ---
    llm = e.get("llm") or {}
    if llm:
        pt = int(llm.get("prompt_tokens") or 0)
        ct = int(llm.get("completion_tokens") or 0)
        provider = llm.get("provider") or ""
        co2, energy = _co2_estimate(pt, ct, provider)
        e["_llm_co2_g"] = co2
        e["_llm_energy_wh"] = energy

    return e


def get_session_summary(sid: str) -> dict:
    events = _session_events.get(sid, [])
    bh = bh_analyze(events)
    fp = fingerprint_session(events)
    return {
        "session_id": sid,
        "phases": _session_phases.get(sid, []),
        "bot": {"verdict": bh.verdict, "confidence": bh.confidence, "signals": bh.signals},
        "fingerprint": fp,
        "command_count": bh.signals.get("command_count", 0),
    }


def cleanup_session(sid: str) -> None:
    _session_events.pop(sid, None)
    _session_phases.pop(sid, None)
