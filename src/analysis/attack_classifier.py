"""
Rule-based attack event classifier inspired by MITRE ATT&CK.
Categories are checked in order — first match wins.
"""
import re
from enum import Enum
from typing import Optional


class Category(str, Enum):
    LOGIN                = "LOGIN"
    RECON                = "RECON"
    DISCOVERY            = "DISCOVERY"
    CREDENTIAL_ACCESS    = "CREDENTIAL_ACCESS"
    EXECUTION            = "EXECUTION"
    PERSISTENCE          = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    LATERAL_MOVEMENT     = "LATERAL_MOVEMENT"
    EXFILTRATION         = "EXFILTRATION"
    IMPACT               = "IMPACT"
    UNKNOWN              = "UNKNOWN"


# (compiled regex, category) — checked in order, first match wins
_RULES: list[tuple[re.Pattern, Category]] = [
    # --- Privilege escalation ---
    (re.compile(r"\b(sudo|doas|pkexec|newgrp)\b"),                          Category.PRIVILEGE_ESCALATION),
    (re.compile(r"\bsu\s*$|\bsu\s+-"),                                       Category.PRIVILEGE_ESCALATION),
    (re.compile(r"\bchmod\s+[0-7]*[0-7][0-7][0-7]\s"),                      Category.PRIVILEGE_ESCALATION),
    (re.compile(r"\b(setuid|setgid|capsh|getcap|setcap)\b"),                 Category.PRIVILEGE_ESCALATION),

    # --- Lateral movement ---
    (re.compile(r"\bssh\s+\S+@\S+"),                                         Category.LATERAL_MOVEMENT),
    (re.compile(r"\b(scp|rsync|sftp)\s+"),                                   Category.LATERAL_MOVEMENT),

    # --- Exfiltration ---
    (re.compile(r"\b(wget|curl)\s+.*https?://"),                             Category.EXFILTRATION),
    (re.compile(r"\bnc\s+.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+"),     Category.EXFILTRATION),
    (re.compile(r"\bscp\s+\S+\s+\S+@\S+:"),                                 Category.EXFILTRATION),
    (re.compile(r"\b(base64|xxd)\b.*\|"),                                    Category.EXFILTRATION),

    # --- Credential access ---
    (re.compile(r"cat\s+/etc/(shadow|gshadow|master\.passwd)"),              Category.CREDENTIAL_ACCESS),
    (re.compile(r"find\s+.*\.(env|pem|key|p12|pfx|crt)\b"),                 Category.CREDENTIAL_ACCESS),
    (re.compile(r"cat\s+.*\.(env|secret|credentials|token|htpasswd|netrc)"),Category.CREDENTIAL_ACCESS),
    (re.compile(r"cat\s+.*\.aws/(credentials|config)"),                     Category.CREDENTIAL_ACCESS),
    (re.compile(r"\b(id_rsa|id_ed25519|id_ecdsa)\b"),                       Category.CREDENTIAL_ACCESS),
    (re.compile(r"\b(mimikatz|secretsdump|hashdump)\b"),                    Category.CREDENTIAL_ACCESS),
    (re.compile(r"(mysql|psql|redis-cli)\s+.*-p\S+"),                       Category.CREDENTIAL_ACCESS),

    # --- Persistence ---
    (re.compile(r"\bcrontab\b"),                                             Category.PERSISTENCE),
    (re.compile(r"/etc/(cron\.|rc\.local|init\.d|profile\.d)"),             Category.PERSISTENCE),
    (re.compile(r"\bsystemctl\s+(enable|start)\b"),                         Category.PERSISTENCE),
    (re.compile(r"\b(adduser|useradd|usermod)\b"),                          Category.PERSISTENCE),
    (re.compile(r"authorized_keys\s*>>"),                                    Category.PERSISTENCE),
    (re.compile(r"\.(bashrc|profile|bash_profile)\s*>>"),                   Category.PERSISTENCE),

    # --- Execution ---
    (re.compile(r"\b(python|python3|perl|ruby|php|node)\s+-[ce]"),          Category.EXECUTION),
    (re.compile(r"\b(bash|sh|zsh|dash)\s+-[ci]\b"),                         Category.EXECUTION),
    (re.compile(r"\b(chmod\s+\+x)\b"),                                      Category.EXECUTION),
    (re.compile(r"\b(nohup|screen|tmux)\s+"),                               Category.EXECUTION),
    (re.compile(r"\b(linpeas|linenum|pspy|chisel|metasploit)\b"),           Category.EXECUTION),
    (re.compile(r"\./\w+"),                                                  Category.EXECUTION),

    # --- Recon ---
    (re.compile(r"\b(whoami|id\b|uname|hostname|hostnamectl)\b"),            Category.RECON),
    (re.compile(r"\b(ifconfig|ip\s+(a|addr|route|link)|netstat|ss\b)\b"),   Category.RECON),
    (re.compile(r"\b(nmap|masscan|zmap|rustscan)\b"),                       Category.RECON),
    (re.compile(r"\bps\s+(aux|ef|a)\b"),                                    Category.RECON),
    (re.compile(r"\b(top|htop|pstree)\b"),                                  Category.RECON),
    (re.compile(r"\b(env\b|printenv)\b"),                                   Category.RECON),
    (re.compile(r"\b(uptime|w\b|who\b|last\b|lastlog)\b"),                  Category.RECON),
    (re.compile(r"cat\s+/proc/(version|cpuinfo|meminfo)"),                  Category.RECON),
    (re.compile(r"\b(lscpu|lsmem|lsblk|dmidecode)\b"),                     Category.RECON),

    # --- Discovery ---
    (re.compile(r"\b(ls|dir|find|locate|which|whereis)\b"),                 Category.DISCOVERY),
    (re.compile(r"cat\s+/etc/(passwd|group|hosts|os-release|issue)"),       Category.DISCOVERY),
    (re.compile(r"\b(df\b|du\b|mount\b|lsof)\b"),                          Category.DISCOVERY),
    (re.compile(r"cat\s+.*\.(conf|cfg|ini|yaml|yml|json|xml|php)\b"),       Category.DISCOVERY),
    (re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD)\s+/"),                  Category.DISCOVERY),

    # --- Impact ---
    (re.compile(r"\brm\s+(-rf?|-r\s)"),                                     Category.IMPACT),
    (re.compile(r"\b(dd\s+if=|mkfs\.|shred\b|wipe\b)\b"),                  Category.IMPACT),
    (re.compile(r"\bkill\s+-9\b"),                                          Category.IMPACT),
    (re.compile(r"\b(iptables|ufw|nft)\s+.*(flush|drop|-F)"),              Category.IMPACT),
]

_CATEGORY_LABELS = {
    Category.LOGIN:                "🔑 LOGIN",
    Category.RECON:                "🔭 RECON",
    Category.DISCOVERY:            "🗂  DISCOVERY",
    Category.CREDENTIAL_ACCESS:    "🔓 CRED_ACCESS",
    Category.EXECUTION:            "⚡ EXECUTION",
    Category.PERSISTENCE:          "🪝 PERSISTENCE",
    Category.PRIVILEGE_ESCALATION: "⬆️  PRIVESC",
    Category.LATERAL_MOVEMENT:     "↔️  LATERAL",
    Category.EXFILTRATION:         "📤 EXFILTRATION",
    Category.IMPACT:               "💥 IMPACT",
    Category.UNKNOWN:              "❓ UNKNOWN",
}


def classify_command(command: str) -> Category:
    cmd = command.strip()
    for pattern, category in _RULES:
        if pattern.search(cmd):
            return category
    return Category.UNKNOWN


def classify_event(event: dict) -> Category:
    if event.get("event_type") in {"auth_attempt", "auth_success", "auth_failure"}:
        return Category.LOGIN
    if "login" in event:
        return Category.LOGIN
    command = _extract_command(event)
    if command:
        return classify_command(command)
    return Category.UNKNOWN


def label(category: Category) -> str:
    return _CATEGORY_LABELS.get(category, category.value)


def _extract_command(event: dict) -> Optional[str]:
    command = event.get("command")
    if isinstance(command, dict):
        return command.get("raw") or command.get("normalized")
    if event.get("command"):
        return str(event["command"])
    if event.get("query"):
        return str(event["query"])
    http = event.get("http-request") or {}
    if isinstance(http, dict) and http.get("path") is not None:
        method = http.get("method", "GET")
        path = http.get("path", "")
        return f"{method} /{path}".rstrip("/")
    return None
