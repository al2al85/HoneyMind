"""
Bot vs human session analyzer.

Two distinct analysis paths:
- Auth-only sessions (no commands): uses session duration, password patterns,
  username rotation, IP frequency across sessions.
- Command sessions: uses timing, typo correction, behavioral patterns, AI traps.
"""
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from analysis.ai_traps import TrapHit, detect_traps


@dataclass
class BotHumanResult:
    verdict: str            # "bot" | "human" | "unclear"
    confidence: float       # 0.0 – 1.0
    signals: dict
    analysis_path: str      # "auth" | "command"
    ai_trap_hits: list[TrapHit] = field(default_factory=list)

    def label(self) -> str:
        icons = {"bot": "🤖 BOT", "human": "🧑 HUMAN", "unclear": "❓ UNCLEAR"}
        pct = int(self.confidence * 100)
        return f"{icons.get(self.verdict, self.verdict)} ({pct}%)"


# ── Shared helpers ────────────────────────────────────────────────────────────

def _extract_commands(events: list[dict]) -> list[str]:
    cmds = []
    for e in events:
        cmd = e.get("command") or {}
        if isinstance(cmd, dict):
            raw = cmd.get("raw") or cmd.get("normalized")
            if raw:
                cmds.append(str(raw))
                continue
        raw = e.get("command") or e.get("query")
        if raw and not isinstance(raw, dict):
            cmds.append(str(raw))
    return cmds


def _extract_delays(events: list[dict]) -> list[int]:
    delays = []
    for e in events:
        timing = e.get("timing") or {}
        ms = timing.get("since_previous_event_ms")
        if ms is None:
            ms = e.get("elapsed_ms")
        if ms is not None and ms >= 0:
            delays.append(int(ms))
    return delays


def _session_duration_ms(events: list[dict]) -> Optional[int]:
    for e in reversed(events):
        details = e.get("details") or {}
        if details.get("duration_ms"):
            return int(details["duration_ms"])
        timing = e.get("timing") or {}
        ms = timing.get("since_session_start_ms")
        if ms:
            return int(ms)
    return None


def _extract_auth_events(events: list[dict]) -> list[dict]:
    return [
        e for e in events
        if e.get("event_type") in ("auth_attempt", "auth_success", "auth_failure")
        or "login" in e
    ]


_WORDLIST_PATTERNS = [
    re.compile(r"^(password|passwd|pass)\d*[!@#]?$", re.I),
    re.compile(r"^(admin|root|user|test|guest)\d*$", re.I),
    re.compile(r"^\d{4,10}$"),                        # pure digits
    re.compile(r"^[a-z]{3,8}\d{1,4}[!@#]?$", re.I),  # word + digits
]

_ROTATING_USERNAMES = {"root", "admin", "ubuntu", "test", "deploy", "user",
                       "oracle", "postgres", "mysql", "pi", "vagrant", "ec2-user"}


# ── Auth-only path ────────────────────────────────────────────────────────────

def _analyze_auth_session(
    events: list[dict],
    all_sessions: Optional[dict] = None,
) -> BotHumanResult:
    """
    Analyze a session with no commands — pure brute-force auth pattern.
    Uses session duration, password patterns, username rotation, IP frequency.
    """
    auth_events = _extract_auth_events(events)
    duration_ms = _session_duration_ms(events)

    # Extract auth data
    passwords: list[str] = []
    usernames: list[str] = []
    client_ip: Optional[str] = None

    for e in auth_events:
        auth = e.get("auth") or e.get("login") or {}
        pwd = auth.get("password")
        user = auth.get("username") or (e.get("client") or {}).get("username")
        ip = (e.get("client") or {}).get("ip") or e.get("client_ip")
        if pwd:
            passwords.append(pwd)
        if user and user not in usernames:
            usernames.append(user)
        if ip:
            client_ip = ip

    # Signal 1: session duration (< 3s = automated)
    is_fast_session = duration_ms is not None and duration_ms < 3000

    # Signal 2: single attempt per session (automated pattern — humans retry)
    single_attempt = len(auth_events) <= 1

    # Signal 3: password matches known wordlist patterns
    wordlist_hits = sum(
        1 for p in passwords
        if any(pat.match(p) for pat in _WORDLIST_PATTERNS)
    )
    wordlist_ratio = wordlist_hits / len(passwords) if passwords else 0.0

    # Signal 4: username is in known automated rotation set
    rotating_username = any(u.lower() in _ROTATING_USERNAMES for u in usernames)

    # Signal 5: IP frequency — how many sessions from this IP in all_sessions
    ip_session_count = 0
    if all_sessions and client_ip:
        for sid, evts in all_sessions.items():
            for e in evts[:2]:  # check first events only for speed
                ip = (e.get("client") or {}).get("ip") or e.get("client_ip")
                if ip == client_ip:
                    ip_session_count += 1
                    break

    # Signal 6: crypto-themed username (targeted bot)
    crypto_target = any(
        kw in u.lower() for u in usernames
        for kw in ("solana", "sol", "eth", "bitcoin", "btc", "crypto", "wallet")
    )

    signals = {
        "analysis_path":     "auth",
        "duration_ms":       duration_ms,
        "fast_session":      is_fast_session,
        "single_attempt":    single_attempt,
        "wordlist_ratio":    round(wordlist_ratio, 2),
        "rotating_username": rotating_username,
        "ip_sessions":       ip_session_count,
        "crypto_target":     crypto_target,
        "auth_count":        len(auth_events),
        "command_count":     0,
        "ai_trap_hits":      0,
    }

    # Scoring
    bot_score = 0.0
    weight_total = 0.0

    def add(score: float, weight: float):
        nonlocal bot_score, weight_total
        bot_score += score * weight
        weight_total += weight

    # Fast session = automated
    if is_fast_session:
        add(1.0, 2.5)
    elif duration_ms is not None and duration_ms < 10000:
        add(0.7, 2.5)
    elif duration_ms is not None:
        add(0.2, 2.5)

    # Single attempt per session = automated (bots connect → try once → disconnect)
    if single_attempt:
        add(0.8, 2.0)
    else:
        add(0.2, 2.0)

    # Wordlist password patterns
    if wordlist_ratio > 0.7:
        add(0.9, 1.5)
    elif wordlist_ratio > 0.3:
        add(0.6, 1.5)
    else:
        add(0.2, 1.5)

    # Rotating username = automated
    if rotating_username:
        add(0.8, 1.0)

    # High IP frequency = definitely automated
    if ip_session_count > 20:
        add(1.0, 2.0)
    elif ip_session_count > 5:
        add(0.8, 2.0)
    elif ip_session_count > 1:
        add(0.5, 2.0)

    # Crypto target = specialized bot
    if crypto_target:
        add(0.9, 1.0)

    confidence = bot_score / weight_total if weight_total > 0 else 0.5

    if confidence >= 0.65:
        verdict, conf = "bot", confidence
    elif confidence <= 0.35:
        verdict, conf = "human", 1.0 - confidence
    else:
        verdict, conf = "unclear", confidence

    return BotHumanResult(
        verdict=verdict,
        confidence=round(conf, 2),
        signals=signals,
        analysis_path="auth",
    )


# ── Command-session path ──────────────────────────────────────────────────────

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
        if 1 <= _levenshtein(a, b) <= 3 and len(a) > 4 and len(b) > 4:
            count += 1
    return count


def _count_paste_bursts(delays: list[int], threshold_ms: int = 100) -> int:
    bursts, streak = 0, 0
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


def _analyze_command_session(events: list[dict], commands: list[str]) -> BotHumanResult:
    delays = _extract_delays(events)
    trap_hits = detect_traps(commands)

    avg_delay = sum(delays) / len(delays) if delays else None
    delay_cv = _coeff_variation([float(d) for d in delays])
    min_delay = min(delays) if delays else None
    paste_bursts = _count_paste_bursts(delays)
    typo_corrections = _count_typo_corrections(commands)
    tool_ratio = sum(1 for c in commands if any(t in c.lower() for t in _KNOWN_TOOLS)) / len(commands)
    systematic = (
        len(commands) >= 5 and
        sum(1 for c in commands if c.strip().startswith(("ls", "cat "))) / len(commands) > 0.6
    )

    signals = {
        "analysis_path":     "command",
        "avg_delay_ms":      round(avg_delay) if avg_delay is not None else None,
        "delay_cv":          round(delay_cv, 2) if delay_cv is not None else None,
        "min_delay_ms":      min_delay,
        "paste_bursts":      paste_bursts,
        "typo_corrections":  typo_corrections,
        "known_tool_ratio":  round(tool_ratio, 2),
        "systematic_enum":   systematic,
        "ai_trap_hits":      len(trap_hits),
        "command_count":     len(commands),
    }

    bot_score = 0.0
    weight_total = 0.0

    def add(score: float, weight: float):
        nonlocal bot_score, weight_total
        bot_score += score * weight
        weight_total += weight

    if trap_hits:
        add(1.0, 3.0)
    if avg_delay is not None:
        add(1.0 if avg_delay < 200 else 0.6 if avg_delay < 800 else 0.3 if avg_delay < 3000 else 0.0, 2.0)
    if delay_cv is not None:
        add(1.0 if delay_cv < 0.2 else 0.5 if delay_cv < 0.5 else 0.0, 1.5)
    if min_delay is not None and min_delay < 50:
        add(1.0, 2.0)
    if paste_bursts > 0:
        add(min(1.0, paste_bursts * 0.4), 1.0)
    add(0.0 if typo_corrections > 0 else 0.5, 1.5 if typo_corrections > 0 else 0.5)
    if tool_ratio > 0.3:
        add(0.8, 1.0)
    elif tool_ratio > 0.1:
        add(0.4, 1.0)
    if systematic:
        add(0.8, 1.0)

    confidence = bot_score / weight_total if weight_total > 0 else 0.5

    if confidence >= 0.65:
        verdict, conf = "bot", confidence
    elif confidence <= 0.35:
        verdict, conf = "human", 1.0 - confidence
    else:
        verdict, conf = "unclear", confidence

    return BotHumanResult(
        verdict=verdict,
        confidence=round(conf, 2),
        signals=signals,
        analysis_path="command",
        ai_trap_hits=trap_hits,
    )


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(
    events: list[dict],
    all_sessions: Optional[dict] = None,
) -> BotHumanResult:
    """
    Analyze a session and return a bot/human verdict.

    Parameters
    ----------
    events      : session events sorted by seq/time
    all_sessions: {session_id: [events]} for IP frequency analysis (optional)
    """
    commands = _extract_commands(events)

    if not commands:
        return _analyze_auth_session(events, all_sessions)
    else:
        return _analyze_command_session(events, commands)
