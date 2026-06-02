"""Bot vs human classification based on behavioral signals."""
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SessionBehavior:
    inter_command_delays_ms: list[float] = field(default_factory=list)
    command_count: int = 0
    typo_corrections: int = 0  # commands following ^C / "command not found" patterns
    paste_bursts: int = 0      # multiple commands with delay < 50ms
    unique_commands: set = field(default_factory=set)
    sequential_enumeration: int = 0  # ls /bin/a, ls /bin/b, ls /bin/c patterns
    auth_attempts: int = 0
    auth_interval_ms: list[float] = field(default_factory=list)


# Commands characteristic of bots (automated enumeration scripts)
_BOT_COMMAND_PATTERNS = [
    re.compile(r"^cat\s+/etc/(passwd|shadow|hosts|issue|os-release)$"),
    re.compile(r"^(uname\s+-a|id|whoami|hostname)$"),
    re.compile(r"^(ls|dir)\s+/?$"),
    re.compile(r"^ifconfig\s*$|^ip\s+addr\s*$"),
    re.compile(r"^ps\s+(aux|ef)\s*$"),
    re.compile(r"^(env|printenv)\s*$"),
    re.compile(r"^(history)\s*$"),
]

# Sequences that look like copy-pasted exploit scripts
_EXPLOIT_SEQUENCE = [
    "uname -a", "id", "whoami", "cat /etc/passwd",
    "cat /etc/shadow", "ls /root", "cat /root/.bash_history",
]


def _is_bot_command(cmd: str) -> bool:
    cmd = cmd.strip()
    for p in _BOT_COMMAND_PATTERNS:
        if p.match(cmd):
            return True
    return False


def score_session(behavior: SessionBehavior) -> dict:
    """Return bot_score (0.0=human, 1.0=bot) and verdict."""
    signals = []

    if behavior.inter_command_delays_ms:
        avg_delay = sum(behavior.inter_command_delays_ms) / len(behavior.inter_command_delays_ms)
        # Bots: very fast (< 200ms avg) or extremely uniform
        if avg_delay < 200:
            signals.append(("fast_timing", 0.6))
        elif avg_delay < 500:
            signals.append(("medium_timing", 0.3))
        else:
            signals.append(("slow_timing", -0.3))

        # Uniformity: low std deviation → bot
        if len(behavior.inter_command_delays_ms) >= 3:
            import statistics
            try:
                std = statistics.stdev(behavior.inter_command_delays_ms)
                cv = std / max(avg_delay, 1)
                if cv < 0.2:  # very uniform
                    signals.append(("uniform_timing", 0.4))
            except statistics.StatisticsError:
                pass

    if behavior.paste_bursts > 2:
        signals.append(("paste_burst", 0.5))

    if behavior.typo_corrections == 0 and behavior.command_count > 5:
        signals.append(("no_typos", 0.2))
    elif behavior.typo_corrections > 0:
        signals.append(("has_typos", -0.4))

    if behavior.sequential_enumeration > 3:
        signals.append(("sequential_enum", 0.4))

    if behavior.auth_attempts > 10:
        signals.append(("bruteforce", 0.7))

    if behavior.command_count > 0:
        bot_cmd_ratio = sum(
            1 for c in behavior.unique_commands if _is_bot_command(c)
        ) / len(behavior.unique_commands)
        if bot_cmd_ratio > 0.6:
            signals.append(("bot_commands", 0.5))

    total = sum(w for _, w in signals)
    # Clamp to [0, 1]
    bot_score = max(0.0, min(1.0, 0.5 + total / max(len(signals), 1) * 0.5)) if signals else 0.5

    if bot_score >= 0.65:
        verdict = "bot"
    elif bot_score <= 0.35:
        verdict = "human"
    else:
        verdict = "unknown"

    return {
        "bot_score": round(bot_score, 3),
        "verdict": verdict,
        "signals": [s for s, _ in signals],
        "avg_delay_ms": round(sum(behavior.inter_command_delays_ms) / max(len(behavior.inter_command_delays_ms), 1), 1),
        "command_count": behavior.command_count,
        "typo_corrections": behavior.typo_corrections,
        "paste_bursts": behavior.paste_bursts,
    }


def update_behavior(behavior: SessionBehavior, event: dict) -> None:
    """Update session behavior from a canonical event."""
    timing = event.get("timing") or {}
    delay = timing.get("since_previous_event_ms")

    if event.get("event_type") == "auth_attempt":
        behavior.auth_attempts += 1
        if delay is not None:
            behavior.auth_interval_ms.append(float(delay))
        return

    if event.get("event_type") != "command":
        return

    behavior.command_count += 1
    cmd_obj = event.get("command")
    if isinstance(cmd_obj, dict):
        raw = cmd_obj.get("raw") or ""
    elif isinstance(cmd_obj, str):
        raw = cmd_obj
    else:
        raw = ""

    if raw:
        behavior.unique_commands.add(raw.strip())

    if delay is not None:
        d = float(delay)
        behavior.inter_command_delays_ms.append(d)
        if d < 50 and len(behavior.inter_command_delays_ms) > 1:
            behavior.paste_bursts += 1

    # Typo detection: very short commands after longer ones (backspace / re-type)
    if raw and len(raw.strip()) <= 3 and behavior.command_count > 1:
        behavior.typo_corrections += 1

    # Sequential enumeration detection
    if re.search(r"(ls|cat|find)\s+\S+[a-z]\d+", raw, re.I):
        behavior.sequential_enumeration += 1
