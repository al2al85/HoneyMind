"""
Bot vs human session analyzer.
Uses timing, typo correction, behavioral patterns and AI trap hits.
"""
from dataclasses import dataclass, field
from typing import Optional

from analysis.ai_traps import TrapHit, detect_traps


@dataclass
class BotHumanResult:
    verdict: str            # "bot" | "human" | "unclear"
    confidence: float       # 0.0 – 1.0
    signals: dict
    ai_trap_hits: list[TrapHit] = field(default_factory=list)

    def label(self) -> str:
        icons = {"bot": "🤖 BOT", "human": "🧑 HUMAN", "unclear": "❓ UNCLEAR"}
        pct = int(self.confidence * 100)
        return f"{icons.get(self.verdict, self.verdict)} ({pct}%)"


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def _extract_delays(events: list[dict]) -> list[int]:
    delays = []
    for e in events:
        # canonical schema
        timing = e.get("timing") or {}
        ms = timing.get("since_previous_event_ms")
        # legacy schema
        if ms is None:
            ms = e.get("elapsed_ms")
        if ms is not None and ms >= 0:
            delays.append(int(ms))
    return delays


def _extract_commands(events: list[dict]) -> list[str]:
    cmds = []
    for e in events:
        # canonical schema
        cmd = e.get("command") or {}
        if isinstance(cmd, dict):
            raw = cmd.get("raw") or cmd.get("normalized")
            if raw:
                cmds.append(str(raw))
                continue
        # legacy schema
        raw = e.get("command") or e.get("query")
        if raw:
            cmds.append(str(raw))
    return cmds


def _coeff_variation(values: list[float]) -> Optional[float]:
    if len(values) < 2:
        return None
    mean = sum(values) / len(values)
    if mean == 0:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return (variance ** 0.5) / mean


def _count_typo_corrections(commands: list[str]) -> int:
    count = 0
    for i in range(1, len(commands)):
        a, b = commands[i - 1].strip(), commands[i].strip()
        if a == b or not a or not b:
            continue
        dist = _levenshtein(a, b)
        # short edit distance but not identical = likely correction
        if 1 <= dist <= 3 and len(a) > 4 and len(b) > 4:
            count += 1
    return count


def _count_paste_bursts(delays: list[int], threshold_ms: int = 100) -> int:
    bursts = 0
    streak = 0
    for d in delays:
        if d < threshold_ms:
            streak += 1
            if streak >= 3:
                bursts += 1
                streak = 0
        else:
            streak = 0
    return bursts


_KNOWN_TOOLS = {
    "nmap", "masscan", "rustscan", "zmap",
    "linpeas", "linenum", "pspy", "lse.sh",
    "chisel", "ligolo", "socat",
    "metasploit", "msfconsole", "msfvenom",
    "sqlmap", "nikto", "gobuster", "ffuf", "wfuzz",
    "hydra", "medusa", "john", "hashcat",
    "mimikatz", "secretsdump",
}

def _known_tool_ratio(commands: list[str]) -> float:
    if not commands:
        return 0.0
    hits = sum(
        1 for cmd in commands
        if any(tool in cmd.lower() for tool in _KNOWN_TOOLS)
    )
    return hits / len(commands)


def _is_systematic_enum(commands: list[str]) -> bool:
    """True if the session exhaustively reads every dir/file it finds."""
    ls_count = sum(1 for c in commands if c.strip().startswith("ls"))
    cat_count = sum(1 for c in commands if c.strip().startswith("cat "))
    if len(commands) < 5:
        return False
    return (ls_count + cat_count) / len(commands) > 0.6


def analyze(events: list[dict]) -> BotHumanResult:
    """
    Analyze a session's events and return a bot/human verdict.
    `events` should be sorted by seq/time.
    """
    commands = _extract_commands(events)
    delays = _extract_delays(events)
    trap_hits = detect_traps(commands)

    # --- compute signals ---
    avg_delay = sum(delays) / len(delays) if delays else None
    delay_cv = _coeff_variation([float(d) for d in delays])
    min_delay = min(delays) if delays else None
    paste_bursts = _count_paste_bursts(delays)
    typo_corrections = _count_typo_corrections(commands)
    tool_ratio = _known_tool_ratio(commands)
    systematic = _is_systematic_enum(commands)

    signals = {
        "avg_delay_ms": round(avg_delay) if avg_delay is not None else None,
        "delay_cv": round(delay_cv, 2) if delay_cv is not None else None,
        "min_delay_ms": min_delay,
        "paste_bursts": paste_bursts,
        "typo_corrections": typo_corrections,
        "known_tool_ratio": round(tool_ratio, 2),
        "systematic_enum": systematic,
        "ai_trap_hits": len(trap_hits),
        "command_count": len(commands),
    }

    # --- score toward "bot" (0 = human, 1 = bot) ---
    bot_score = 0.0
    weight_total = 0.0

    def add(score: float, weight: float):
        nonlocal bot_score, weight_total
        bot_score += score * weight
        weight_total += weight

    # AI trap hit → near-certain bot/AI agent
    if trap_hits:
        add(1.0, 3.0)

    # Very fast average delay
    if avg_delay is not None:
        if avg_delay < 200:
            add(1.0, 2.0)
        elif avg_delay < 800:
            add(0.6, 2.0)
        elif avg_delay < 3000:
            add(0.3, 2.0)
        else:
            add(0.0, 2.0)

    # Very regular timing (low CV = bot)
    if delay_cv is not None:
        if delay_cv < 0.2:
            add(1.0, 1.5)
        elif delay_cv < 0.5:
            add(0.5, 1.5)
        else:
            add(0.0, 1.5)

    # Impossible human speed
    if min_delay is not None and min_delay < 50:
        add(1.0, 2.0)

    # Paste bursts
    if paste_bursts > 0:
        add(min(1.0, paste_bursts * 0.4), 1.0)

    # Typo corrections = human signal (subtract)
    if typo_corrections > 0:
        add(0.0, 1.5)  # pulls toward human
    else:
        add(0.5, 0.5)  # slight bot lean if no typos

    # Known tools
    if tool_ratio > 0.3:
        add(0.8, 1.0)
    elif tool_ratio > 0.1:
        add(0.4, 1.0)

    # Systematic enumeration
    if systematic:
        add(0.8, 1.0)

    confidence = bot_score / weight_total if weight_total > 0 else 0.5

    if confidence >= 0.65:
        verdict = "bot"
    elif confidence <= 0.35:
        verdict = "human"
        confidence = 1.0 - confidence
    else:
        verdict = "unclear"

    return BotHumanResult(
        verdict=verdict,
        confidence=round(confidence, 2),
        signals=signals,
        ai_trap_hits=trap_hits,
    )
