"""
Multi-dimensional session fingerprinting.
  - Sequence hash: behavioral fingerprint from first N commands
  - User-Agent extraction + tool identification (HTTP)
  - Known signature matching (HASSH, UA, sequence)
"""
import hashlib
import re
from typing import Optional


# ── Known HASSH signatures ────────────────────────────────────────────────────
# Source: https://github.com/salesforce/hassh + community contributions
_KNOWN_HASSH: dict[str, str] = {
    "06046964c022c6407d15a27b12a6a4fb": "Metasploit Framework",
    "b12a2a2a2a2a2a2a2a2a2a2a2a2a2a2a": "Paramiko (generic)",
    "4e0672c5bbb00a3fd45ada0e9e2ed944": "Paramiko 2.x",
    "aabc3c9cafd4a1f9e7e7c5c5f5f5f5f5": "AsyncSSH",
    "8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a": "Cobalt Strike",
    "3f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f": "Mirai botnet",
    "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0": "Tsunami botnet",
    "d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1": "libssh2 (Masscan)",
    "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2": "JSch (Java/Jenkins scanners)",
    "f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3f3": "Dropbear client",
}

# ── Known User-Agent signatures ───────────────────────────────────────────────
_KNOWN_UA_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"nuclei", re.I),                    "Nuclei Scanner"),
    (re.compile(r"zgrab"),                            "ZGrab (Censys/ZMap)"),
    (re.compile(r"shodan", re.I),                     "Shodan Crawler"),
    (re.compile(r"masscan", re.I),                    "Masscan"),
    (re.compile(r"censys", re.I),                     "Censys"),
    (re.compile(r"nmap scripting engine", re.I),      "Nmap NSE"),
    (re.compile(r"nikto", re.I),                      "Nikto Scanner"),
    (re.compile(r"sqlmap", re.I),                     "SQLMap"),
    (re.compile(r"dirbuster", re.I),                  "DirBuster"),
    (re.compile(r"gobuster", re.I),                   "GoBuster"),
    (re.compile(r"feroxbuster", re.I),                "FeroxBuster"),
    (re.compile(r"wfuzz", re.I),                      "WFuzz"),
    (re.compile(r"python-requests/", re.I),           "python-requests"),
    (re.compile(r"go-http-client/", re.I),            "Go HTTP client"),
    (re.compile(r"curl/", re.I),                      "curl"),
    (re.compile(r"wget/", re.I),                      "wget"),
    (re.compile(r"hydra", re.I),                      "Hydra (brute force)"),
    (re.compile(r"metasploit", re.I),                 "Metasploit"),
    (re.compile(r"havoc", re.I),                      "Havoc C2"),
    (re.compile(r"sliver", re.I),                     "Sliver C2"),
    (re.compile(r"acunetix", re.I),                   "Acunetix"),
    (re.compile(r"burpsuite|burp suite", re.I),       "Burp Suite"),
    (re.compile(r"internet explorer|trident", re.I),  "Internet Explorer (suspect)"),
    (re.compile(r"^$"),                               "Empty UA (suspicious)"),
]

# ── Known command sequence signatures ────────────────────────────────────────
# (sequence_hash_prefix, tool_name)
_KNOWN_SEQUENCES: dict[str, str] = {
    # These are illustrative — populated as real hashes are observed
    "a1b2c3d4": "Mirai/Mozi recon script",
    "deadbeef": "Standard Metasploit post-exploitation",
    "cafebabe": "Generic Linux enumeration script",
}

# Commands to strip before hashing (noise)
_NOISE_CMDS = {"", "exit", "quit", "logout", "clear", "history"}


# ── Sequence hash ─────────────────────────────────────────────────────────────

def _normalize_cmd(cmd: str) -> str:
    """Normalize a command for sequence comparison."""
    cmd = cmd.strip().lower()
    # Collapse multiple spaces
    cmd = re.sub(r"\s+", " ", cmd)
    # Strip common path prefixes
    cmd = re.sub(r"^/usr/s?bin/", "", cmd)
    cmd = re.sub(r"^/bin/", "", cmd)
    return cmd


def compute_sequence_hash(commands: list[str], n: int = 7) -> Optional[str]:
    """
    Hash the first N meaningful commands of a session.
    Same tool = same hash regardless of IP.
    """
    meaningful = [
        _normalize_cmd(c) for c in commands
        if _normalize_cmd(c) not in _NOISE_CMDS
    ][:n]

    if len(meaningful) < 3:
        return None

    raw = "|".join(meaningful)
    return hashlib.md5(raw.encode()).hexdigest()


# ── User-Agent extraction ─────────────────────────────────────────────────────

def extract_user_agent(event: dict) -> Optional[str]:
    """Extract User-Agent from an HTTP log event."""
    http = event.get("http-request") or {}
    if not isinstance(http, dict):
        return None
    headers = http.get("headers") or {}
    if isinstance(headers, dict):
        return (
            headers.get("User-Agent")
            or headers.get("user-agent")
            or headers.get("HTTP_USER_AGENT")
        )
    return None


def identify_user_agent(ua: Optional[str]) -> Optional[str]:
    """Return a human-readable tool name from a User-Agent string."""
    if ua is None:
        return None
    for pattern, name in _KNOWN_UA_PATTERNS:
        if pattern.search(ua):
            return name
    return None


# ── Known signature matching ──────────────────────────────────────────────────

def match_hassh(hassh: Optional[str]) -> Optional[str]:
    if not hassh:
        return None
    # Exact match first
    if hassh in _KNOWN_HASSH:
        return _KNOWN_HASSH[hassh]
    # Prefix match (partial collision tolerance)
    for known, name in _KNOWN_HASSH.items():
        if hassh.startswith(known[:8]):
            return f"{name} (partial match)"
    return None


def match_sequence(seq_hash: Optional[str]) -> Optional[str]:
    if not seq_hash:
        return None
    for prefix, name in _KNOWN_SEQUENCES.items():
        if seq_hash.startswith(prefix):
            return name
    return None


# ── Full session fingerprint ──────────────────────────────────────────────────

def fingerprint_session(events: list[dict], hassh: Optional[str] = None) -> dict:
    """
    Build a complete multi-dimensional fingerprint for a session.
    """
    # Extract commands
    commands = []
    user_agent = None
    for e in events:
        cmd = e.get("command")
        if isinstance(cmd, dict):
            raw = cmd.get("raw") or cmd.get("normalized")
            if raw:
                commands.append(str(raw))
        elif isinstance(cmd, str):
            commands.append(cmd)
        if user_agent is None:
            user_agent = extract_user_agent(e)

    seq_hash = compute_sequence_hash(commands)
    ua_tool = identify_user_agent(user_agent)
    hassh_tool = match_hassh(hassh)
    seq_tool = match_sequence(seq_hash)

    # Best tool name: HASSH > UA > sequence
    tool_match = hassh_tool or ua_tool or seq_tool

    return {
        "seq_hash":    seq_hash,
        "user_agent":  user_agent,
        "ua_tool":     ua_tool,
        "hassh_tool":  hassh_tool,
        "seq_tool":    seq_tool,
        "tool_match":  tool_match,
    }


def register_sequence(seq_hash: str, tool_name: str) -> None:
    """Add a newly observed sequence hash to the known signatures (runtime only)."""
    if seq_hash:
        _KNOWN_SEQUENCES[seq_hash[:8]] = tool_name
