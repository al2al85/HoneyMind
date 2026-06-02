"""
Log condenser: compress raw session events into a compact LLM-friendly representation.

Goal: reduce token usage by 80–95% while preserving all analytically relevant information.

Compression strategies:
- Deduplicate repeated commands (same cmd N times → {cmd, count})
- Merge auth attempts into a summary
- Extract files accessed as a list
- Keep only unique passwords tried (not all 47 attempts)
- Represent phases as ordered list instead of per-event
"""
from collections import Counter, defaultdict
from typing import Optional

from analysis.attack_classifier import classify_event, Category, _extract_command


def _extract_files(commands: list[str]) -> list[str]:
    """Extract file paths accessed from command list."""
    import re
    files = []
    pattern = re.compile(r'(?:cat|less|more|head|tail|nano|vi|vim|type)\s+(\S+)')
    for cmd in commands:
        m = pattern.search(cmd)
        if m:
            path = m.group(1)
            if path not in files:
                files.append(path)
    return files


def _extract_tools(commands: list[str]) -> list[str]:
    """Identify known attack tools used."""
    from analysis.session_fingerprint import _KNOWN_TOOLS
    found = []
    for cmd in commands:
        for tool in _KNOWN_TOOLS:
            if tool in cmd.lower() and tool not in found:
                found.append(tool)
    return found


def condense_session(events: list[dict]) -> dict:
    """
    Compress a session's events into a compact dict for LLM analysis.
    Typical compression: 100 events → ~30 tokens.
    """
    if not events:
        return {}

    first = events[0]

    # Client info
    client = first.get("client") or {}
    ip = client.get("ip") or first.get("client_ip") or "?"
    username = client.get("username") or first.get("username")
    protocol = first.get("service") or first.get("protocol") or first.get("type") or "?"
    port = (first.get("honeypot") or {}).get("port") or first.get("port")

    # Timing
    time_start = (first.get("timestamp") or first.get("time") or "")[:19]
    time_end = (events[-1].get("timestamp") or events[-1].get("time") or "")[:19]
    timing = events[-1].get("timing") or {}
    duration_ms = timing.get("since_session_start_ms")

    # Auth attempts
    auth_events = [e for e in events if "login" in e or e.get("event_type") in ("auth_attempt", "auth_success", "auth_failure")]
    auth_summary = _condense_auth(auth_events)

    # Commands — deduplicated with counts
    raw_commands = []
    for e in events:
        cmd = _extract_command(e)
        if cmd:
            raw_commands.append(cmd)

    cmd_counts = Counter(raw_commands)
    condensed_commands = [
        {"cmd": cmd, "count": count} if count > 1 else {"cmd": cmd}
        for cmd, count in cmd_counts.most_common()
    ]

    # Attack phases (ordered, deduplicated)
    phases = []
    seen_phases = set()
    for e in events:
        cat = classify_event(e)
        if cat != Category.UNKNOWN and cat.value not in seen_phases:
            seen_phases.add(cat.value)
            phases.append(cat.value)

    # Files accessed
    files_accessed = _extract_files(raw_commands)

    # Tools detected
    tools = _extract_tools(raw_commands)

    # Fingerprint
    ssh_fp = next((e.get("ssh_fingerprint") for e in events if e.get("ssh_fingerprint")), None)

    result = {
        "session_id": first.get("session_id") or first.get("session-id"),
        "ip": ip,
        "protocol": f"{protocol}:{port}" if port else protocol,
        "time_start": time_start,
        "time_end": time_end,
        "duration_ms": duration_ms,
        "username": username,
        "event_count": len(events),
        "phases": phases,
        "auth": auth_summary or None,
        "commands": condensed_commands,
        "files_accessed": files_accessed or None,
        "tools_detected": tools or None,
    }

    if ssh_fp:
        result["fingerprint"] = {
            "client": ssh_fp.get("client_name"),
            "hassh": (ssh_fp.get("hassh") or "")[:8] or None,
        }

    # Remove None values to save tokens
    return {k: v for k, v in result.items() if v is not None}


def _condense_auth(auth_events: list[dict]) -> Optional[dict]:
    if not auth_events:
        return None

    passwords = []
    usernames = []
    success = False
    successful_user = None
    successful_password = None

    for e in auth_events:
        login = e.get("login") or {}
        auth = e.get("auth") or {}

        pwd = login.get("password") or auth.get("password")
        user = login.get("username") or (e.get("client") or {}).get("username")
        ok = login.get("success") or auth.get("success")

        if pwd and pwd not in passwords:
            passwords.append(pwd)
        if user and user not in usernames:
            usernames.append(user)
        if ok:
            success = True
            successful_user = user
            successful_password = pwd

    summary = {
        "attempts": len(auth_events),
        "unique_passwords": len(passwords),
        "usernames_tried": usernames[:5],
        "passwords_sample": passwords[:5],
        "success": success,
    }
    if success:
        summary["successful_user"] = successful_user
        summary["successful_password"] = successful_password

    return summary


def condense_sessions(sessions: dict[str, list[dict]]) -> dict:
    condensed = [condense_session(events) for events in sessions.values() if events]
    all_ips = [s["ip"] for s in condensed if s.get("ip") and s["ip"] != "?"]
    all_phases = [phase for s in condensed for phase in (s.get("phases") or [])]
    all_cmds = [c["cmd"] for s in condensed for c in (s.get("commands") or [])]
    return {
        "summary": {
            "total_sessions": len(condensed),
            "unique_ips": len(set(all_ips)),
            "attack_phases": dict(Counter(all_phases).most_common()),
            "top_commands": [
                {"cmd": cmd, "count": count}
                for cmd, count in Counter(all_cmds).most_common(15)
            ],
        },
        "sessions": condensed,
    }


def condense_multidimensional(
    sessions: dict[str, list[dict]],
    bot_human_results: Optional[dict] = None,
    ip_cache: Optional[dict] = None,
    campaigns: Optional[list] = None,
    attacker_profiles: Optional[dict] = None,
) -> dict:
    """
    Full multidimensional condensation across all factorization criteria.
    Produces a compact structure covering every analytical dimension.

    Parameters
    ----------
    sessions          : raw events per session_id
    bot_human_results : {session_id: BotHumanResult}
    ip_cache          : {ip: ip_enricher result}
    campaigns         : list of Campaign objects from campaign_detector
    attacker_profiles : {session_id: profile dict from attacker_profiler}
    """
    bot_human_results  = bot_human_results  or {}
    ip_cache           = ip_cache           or {}
    campaigns          = campaigns          or []
    attacker_profiles  = attacker_profiles  or {}

    condensed_sessions = {
        sid: condense_session(events)
        for sid, events in sessions.items() if events
    }

    all_events = [e for evts in sessions.values() for e in evts]
    all_ips    = [s["ip"] for s in condensed_sessions.values() if s.get("ip") and s["ip"] != "?"]
    all_cmds   = [c["cmd"] for s in condensed_sessions.values() for c in (s.get("commands") or [])]
    all_files  = [f for s in condensed_sessions.values() for f in (s.get("files_accessed") or [])]

    # ── Behavior ─────────────────────────────────────────────────────────────
    behavior_counts: dict[str, int] = Counter()
    sophistication_counts: dict[str, int] = Counter()
    ai_trap_sessions = 0

    for sid, bh in bot_human_results.items():
        behavior_counts[bh.verdict] += 1
        if bh.signals.get("ai_trap_hits", 0) > 0:
            ai_trap_sessions += 1

    for sid, prof in attacker_profiles.items():
        sophistication_counts[prof.get("profile_type", "unknown")] += 1

    total = len(condensed_sessions) or 1

    behavior = {
        "bot":      {"sessions": behavior_counts.get("bot", 0),     "pct": round(behavior_counts.get("bot", 0)     * 100 / total)},
        "human":    {"sessions": behavior_counts.get("human", 0),   "pct": round(behavior_counts.get("human", 0)   * 100 / total)},
        "unclear":  {"sessions": behavior_counts.get("unclear", 0), "pct": round(behavior_counts.get("unclear", 0) * 100 / total)},
        "ai_agent_sessions": ai_trap_sessions,
        "sophistication": dict(sophistication_counts.most_common()),
    }

    # ── Technique ─────────────────────────────────────────────────────────────
    tool_groups:     dict[str, list] = defaultdict(list)
    phase_counts:    Counter         = Counter()
    protocol_counts: Counter         = Counter()
    result_counts:   Counter         = Counter()

    for sid, s in condensed_sessions.items():
        tool = s.get("fingerprint", {}).get("client") or s.get("tools_detected", [None])[0] if s.get("tools_detected") else None
        if tool:
            tool_groups[tool].append(s)

        for phase in (s.get("phases") or []):
            phase_counts[phase] += 1

        proto = (s.get("protocol") or "unknown").split(":")[0]
        protocol_counts[proto] += 1

        auth = s.get("auth") or {}
        if auth.get("success"):
            result_counts["success"] += 1
        elif auth.get("attempts", 0) > 0:
            result_counts["failed"] += 1
        else:
            result_counts["no_auth"] += 1

    technique = {
        "by_tool": {
            tool: {
                "sessions": len(slist),
                "top_commands": list({
                    c["cmd"] for s in slist for c in (s.get("commands") or [])
                })[:5],
            }
            for tool, slist in sorted(tool_groups.items(), key=lambda x: -len(x[1]))
        },
        "by_dominant_phase": dict(phase_counts.most_common()),
        "by_protocol": dict(protocol_counts.most_common()),
        "by_result": dict(result_counts),
    }

    # ── Network ───────────────────────────────────────────────────────────────
    country_counts: Counter = Counter()
    anon_counts:    Counter = Counter()

    for ip in set(all_ips):
        data = ip_cache.get(ip) or {}
        cc = data.get("country_code") or data.get("country") or "unknown"
        country_counts[cc] += 1
        anon_type = data.get("anonymization_type") or "unknown"
        anon_counts[anon_type] += 1

    campaign_summaries = []
    for c in campaigns:
        campaign_summaries.append({
            "id":       c.campaign_id,
            "verdict":  c.verdict,
            "sessions": c.session_count,
            "ips":      len(c.ips),
            "tool":     next((cmd for cmd in c.shared_commands if cmd.startswith("[")), None),
            "shared":   [cmd for cmd in c.shared_commands if not cmd.startswith("[")][:5],
            "window":   f"{(c.time_start or '')[:16]} → {(c.time_end or '')[:16]}",
            "confidence": f"{int(c.confidence * 100)}%",
        })

    network = {
        "campaigns":        campaign_summaries,
        "by_country":       dict(country_counts.most_common(10)),
        "by_anonymization": dict(anon_counts.most_common()),
    }

    # ── Temporal ──────────────────────────────────────────────────────────────
    times = sorted(
        filter(None, [
            (s.get("time_start") or "")[:16]
            for s in condensed_sessions.values()
        ])
    )
    hour_counts: Counter = Counter()
    for s in condensed_sessions.values():
        t = s.get("time_start") or ""
        if len(t) >= 13:
            try:
                hour_counts[int(t[11:13])] += 1
            except ValueError:
                pass

    peak_hour = hour_counts.most_common(1)[0][0] if hour_counts else None
    durations = [
        s["duration_ms"] for s in condensed_sessions.values()
        if s.get("duration_ms")
    ]
    slow_attacks = sum(1 for d in durations if d > 300_000)  # > 5 min

    temporal = {
        "period_start":  times[0]  if times else None,
        "period_end":    times[-1] if times else None,
        "peak_hour_utc": peak_hour,
        "slow_attacks":  slow_attacks,
        "hourly_distribution": {
            str(h): c for h, c in sorted(hour_counts.items())
        },
    }

    # ── Content ───────────────────────────────────────────────────────────────
    file_counts = Counter(all_files)
    cmd_counts  = Counter(all_cmds)

    _CRED_FILES   = {"/etc/shadow", "/etc/passwd", ".env", "credentials", "id_rsa", ".aws"}
    _CONFIG_FILES = {".conf", ".cfg", ".ini", ".php", ".yml", ".yaml"}

    file_categories: dict[str, int] = defaultdict(int)
    for f in all_files:
        if any(c in f for c in _CRED_FILES):
            file_categories["credentials"] += 1
        elif any(f.endswith(ext) for ext in _CONFIG_FILES):
            file_categories["config"] += 1
        elif "/log" in f:
            file_categories["logs"] += 1
        else:
            file_categories["other"] += 1

    content = {
        "top_files": [
            {"file": f, "sessions": c}
            for f, c in file_counts.most_common(10)
        ],
        "file_categories": dict(file_categories),
        "top_commands": [
            {"cmd": cmd, "sessions": c}
            for cmd, c in cmd_counts.most_common(15)
        ],
        "ai_traps_triggered": ai_trap_sessions,
        "most_targeted_protocol": protocol_counts.most_common(1)[0][0] if protocol_counts else None,
    }

    return {
        "meta": {
            "total_sessions": len(condensed_sessions),
            "unique_ips":     len(set(all_ips)),
            "total_events":   sum(len(e) for e in sessions.values()),
        },
        "behavior":  behavior,
        "technique": technique,
        "network":   network,
        "temporal":  temporal,
        "content":   content,
    }


def estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token for English/code."""
    return len(text) // 4


def compression_ratio(original_events: int, condensed_text: str) -> str:
    original_tokens = original_events * 60  # ~60 tokens per raw event
    condensed_tokens = estimate_tokens(condensed_text)
    ratio = original_tokens / condensed_tokens if condensed_tokens else 0
    return f"{ratio:.1f}x ({original_tokens} → {condensed_tokens} tokens)"
