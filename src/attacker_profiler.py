"""
Attacker profiling: sophistication score + narrative from IP data + behavior.
"""
from typing import Optional
from attack_classifier import Category


_PROFILE_TYPES = {
    (0, 3):  ("script_kiddie",  "Script Kiddie"),
    (4, 5):  ("opportunist",    "Opportuniste"),
    (6, 8):  ("targeted",       "Attaquant ciblé"),
    (9, 10): ("nation_state",   "Acteur sophistiqué / APT"),
}

_HIGH_RISK_COUNTRIES = {"KP", "IR", "RU", "CN"}

_ANON_LABELS = {
    "tor":           "via Tor",
    "vpn_commercial": "via VPN commercial",
    "proxy":         "via proxy",
    "datacenter":    "depuis un VPS/datacenter",
    "residential":   "depuis une IP résidentielle (machine compromise ?)",
    "unknown":       "anonymisation inconnue",
}


def profile(
    ip_data: dict,
    bh_result,            # BotHumanResult from bot_human_analyzer
    categories: set,      # set of Category
    local_hour: Optional[int] = None,
) -> dict:

    score = 0
    flags = []

    # --- anonymization ---
    anon = ip_data.get("anonymization_type", "unknown")
    anon_level = ip_data.get("anonymization_level", 0)

    if anon == "residential":
        score += 3
        flags.append("machine_compromise_suspected")
    elif anon == "vpn_commercial":
        score += 2
    elif anon == "tor":
        score += 1
    elif anon == "datacenter":
        score += 0

    # --- behavior ---
    if bh_result.verdict == "human":
        score += 2
    elif bh_result.verdict == "unclear":
        score += 1

    # --- command sophistication ---
    advanced_categories = {
        Category.PRIVILEGE_ESCALATION,
        Category.LATERAL_MOVEMENT,
        Category.PERSISTENCE,
        Category.EXFILTRATION,
    }
    if advanced_categories & categories:
        score += 2

    if bh_result.signals.get("known_tool_ratio", 0) < 0.2 and len(categories) > 3:
        score += 2  # custom/unknown tools with broad coverage

    # --- AI trap hit (lowers sophistication — fell for a trap) ---
    if bh_result.signals.get("ai_trap_hits", 0) > 0:
        flags.append("ai_agent")
        score = max(0, score - 1)

    # --- geopolitical flags ---
    cc = ip_data.get("country_code")
    if cc in _HIGH_RISK_COUNTRIES:
        flags.append("geopolitical")

    # --- timing correlation ---
    if local_hour is not None:
        if 9 <= local_hour <= 18:
            flags.append("business_hours_local")
            if bh_result.verdict == "human":
                score += 1
        elif 0 <= local_hour <= 5:
            flags.append("night_local")

    score = min(10, score)

    # --- profile type ---
    profile_id, profile_label = "opportunist", "Opportuniste"
    for (lo, hi), (pid, plabel) in _PROFILE_TYPES.items():
        if lo <= score <= hi:
            profile_id, profile_label = pid, plabel
            break

    narrative = _build_narrative(ip_data, bh_result, categories, anon, flags, local_hour)

    return {
        "sophistication_score": score,
        "profile_type": profile_id,
        "profile_label": profile_label,
        "flags": flags,
        "narrative": narrative,
    }


def _build_narrative(ip_data, bh_result, categories, anon, flags, local_hour) -> str:
    parts = []

    # agent type
    if "ai_agent" in flags:
        parts.append("Agent IA automatisé")
    elif bh_result.verdict == "bot":
        parts.append("Bot automatisé")
    elif bh_result.verdict == "human":
        parts.append("Attaquant humain")
    else:
        parts.append("Origine incertaine")

    # location
    location = ", ".join(filter(None, [ip_data.get("city"), ip_data.get("country")]))
    if location:
        parts.append(f"depuis {location}")

    # anonymization
    anon_label = _ANON_LABELS.get(anon)
    if anon_label:
        parts.append(anon_label)

    # timing
    if local_hour is not None:
        if "business_hours_local" in flags:
            parts.append("opérant pendant ses heures de bureau")
        elif "night_local" in flags:
            parts.append("attaquant en pleine nuit locale (probablement automatisé ou autre fuseau)")

    # objectives
    obj_parts = []
    if Category.CREDENTIAL_ACCESS in categories:
        obj_parts.append("vol de credentials")
    if Category.EXFILTRATION in categories:
        obj_parts.append("exfiltration de données")
    if Category.PERSISTENCE in categories:
        obj_parts.append("persistance")
    if Category.LATERAL_MOVEMENT in categories:
        obj_parts.append("mouvement latéral")
    if obj_parts:
        parts.append(f"— objectifs : {', '.join(obj_parts)}")

    return " ".join(parts) + "."


_SCORE_ICONS = {
    (0, 3): "🟢",
    (4, 5): "🟡",
    (6, 8): "🟠",
    (9, 10): "🔴",
}


def score_icon(score: int) -> str:
    for (lo, hi), icon in _SCORE_ICONS.items():
        if lo <= score <= hi:
            return icon
    return "⚪"
