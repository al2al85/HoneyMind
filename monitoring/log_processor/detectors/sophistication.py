"""Attacker sophistication scoring (low / medium / high)."""
from typing import Optional


_HIGH_SOPHISTICATION_TOOLS = {
    "cobalt-strike", "sliver", "empire", "metasploit",
    "chisel", "msfvenom", "log4shell",
}
_MEDIUM_SOPHISTICATION_TOOLS = {
    "nmap", "linpeas", "linenum", "pspy", "sqlmap",
    "hydra", "nikto", "web-fuzzer", "wpscan",
}

_HIGH_CATEGORIES = {"PRIVILEGE_ESCALATION", "LATERAL_MOVEMENT", "EXFILTRATION"}
_MEDIUM_CATEGORIES = {"EXECUTION", "PERSISTENCE", "CREDENTIAL_ACCESS"}


def score_sophistication(
    tools: list[str],
    categories_seen: list[str],
    phase_count: int,
    command_count: int,
    used_obfuscation: bool = False,
) -> str:
    """Return 'low', 'medium', or 'high'."""
    score = 0

    tool_set = set(tools)
    if tool_set & _HIGH_SOPHISTICATION_TOOLS:
        score += 3
    elif tool_set & _MEDIUM_SOPHISTICATION_TOOLS:
        score += 2
    else:
        score += 0

    cat_set = set(categories_seen)
    if cat_set & _HIGH_CATEGORIES:
        score += 3
    elif cat_set & _MEDIUM_CATEGORIES:
        score += 2

    if phase_count >= 5:
        score += 2
    elif phase_count >= 3:
        score += 1

    if used_obfuscation:
        score += 2

    if command_count > 50:
        score += 1

    if score >= 6:
        return "high"
    elif score >= 3:
        return "medium"
    return "low"


def detect_obfuscation(command: str) -> bool:
    """Detect base64, hex encoding, eval tricks, etc."""
    import re
    patterns = [
        r"\bbase64\b",
        r"\beval\b.*\$\(",
        r"\$\(echo.*\|.*base64",
        r"\\x[0-9a-fA-F]{2}",
        r"printf\s+['\"]\\\\x",
        r"\bIFS=",
        r"\b[A-Za-z_]+=.*&&.*\$[A-Za-z_]+",  # variable obfuscation
    ]
    for p in patterns:
        if re.search(p, command, re.I):
            return True
    return False
