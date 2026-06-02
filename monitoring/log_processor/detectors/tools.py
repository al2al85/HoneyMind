"""Detect attacker tools from commands and user-agents."""
import re
from typing import Optional

_TOOL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bnmap\b", re.I),                          "nmap"),
    (re.compile(r"\bmasscan\b", re.I),                       "masscan"),
    (re.compile(r"\brusstscan\b|\brustscan\b", re.I),        "rustscan"),
    (re.compile(r"\bzmap\b", re.I),                          "zmap"),
    (re.compile(r"\bmetasploit\b|\bmsfconsole\b|\bmsf\b", re.I), "metasploit"),
    (re.compile(r"\bmsfvenom\b", re.I),                      "msfvenom"),
    (re.compile(r"\bsqlmap\b", re.I),                        "sqlmap"),
    (re.compile(r"\bhydra\b", re.I),                         "hydra"),
    (re.compile(r"\bmedusa\b", re.I),                        "medusa"),
    (re.compile(r"\bjohn\b.*password|\bjtr\b", re.I),        "john-the-ripper"),
    (re.compile(r"\bhashcat\b", re.I),                       "hashcat"),
    (re.compile(r"\blinpeas\b", re.I),                       "linpeas"),
    (re.compile(r"\blinenum\b", re.I),                       "linenum"),
    (re.compile(r"\bpspy\b", re.I),                          "pspy"),
    (re.compile(r"\bchisel\b", re.I),                        "chisel"),
    (re.compile(r"\bsliver\b", re.I),                        "sliver"),
    (re.compile(r"\bcobalt.strike\b|\bbeacon\b", re.I),      "cobalt-strike"),
    (re.compile(r"\bempire\b", re.I),                        "empire"),
    (re.compile(r"\bnikto\b", re.I),                         "nikto"),
    (re.compile(r"\bdirbuster\b|\bgobuster\b|\bffuf\b", re.I), "web-fuzzer"),
    (re.compile(r"\bburp\b|\bbsuite\b", re.I),               "burpsuite"),
    (re.compile(r"\bwgetspider\b|\bsitemap\b", re.I),        "crawler"),
    (re.compile(r"\bwpwn\b|\bwpscan\b", re.I),               "wpscan"),
    (re.compile(r"\bstruts\b", re.I),                        "struts-exploit"),
    (re.compile(r"\blog4j\b|\bjndi:\b", re.I),               "log4shell"),
    (re.compile(r"\bshellshock\b|\b\(\)\s*\{", re.I),        "shellshock"),
    (re.compile(r"\bmirai\b", re.I),                         "mirai"),
    (re.compile(r"\bxmrig\b|\bminerd\b", re.I),              "cryptominer"),
    (re.compile(r"\bnetcat\b|\bnc\s+-[le]", re.I),           "netcat"),
    (re.compile(r"\bsocat\b", re.I),                         "socat"),
    (re.compile(r"\bpowercat\b", re.I),                      "powercat"),
    (re.compile(r"\btcpdump\b|\bwireshark\b", re.I),         "packet-capture"),
]

_UA_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"zgrab", re.I),        "zgrab"),
    (re.compile(r"masscan", re.I),      "masscan"),
    (re.compile(r"nmap", re.I),         "nmap"),
    (re.compile(r"python-requests", re.I), "python-requests"),
    (re.compile(r"go-http-client", re.I),  "go-http"),
    (re.compile(r"curl/", re.I),        "curl"),
    (re.compile(r"wget/", re.I),        "wget"),
    (re.compile(r"nikto", re.I),        "nikto"),
    (re.compile(r"dirbuster", re.I),    "dirbuster"),
    (re.compile(r"sqlmap", re.I),       "sqlmap"),
    (re.compile(r"libwww-perl", re.I),  "libwww-perl"),
    (re.compile(r"shodan", re.I),       "shodan"),
    (re.compile(r"censys", re.I),       "censys"),
]

_ANONYMIZATION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\btor\b|\b\.onion\b", re.I),               "tor"),
    (re.compile(r"\bproxychains\b", re.I),                   "proxychains"),
    (re.compile(r"\btorsocks\b", re.I),                      "torsocks"),
    (re.compile(r"\bopenvpn\b|\bwireguard\b", re.I),         "vpn"),
    (re.compile(r"\bi2p\b", re.I),                           "i2p"),
]

_UPLOADED_FILE_EXTENSIONS = {
    ".sh", ".py", ".pl", ".rb", ".php", ".elf", ".exe",
    ".bat", ".ps1", ".jar", ".so", ".bin",
}


def detect_tools(command: str) -> list[str]:
    found = []
    for pattern, tool in _TOOL_PATTERNS:
        if pattern.search(command):
            found.append(tool)
    return found


def detect_ua_tool(user_agent: Optional[str]) -> Optional[str]:
    if not user_agent:
        return None
    for pattern, tool in _UA_PATTERNS:
        if pattern.search(user_agent):
            return tool
    return None


def detect_anonymization(command: str) -> list[str]:
    found = []
    for pattern, tool in _ANONYMIZATION_PATTERNS:
        if pattern.search(command):
            found.append(tool)
    return found


def detect_uploaded_file(command: str) -> Optional[str]:
    """Return filename if a script/binary upload is detected."""
    # wget/curl to download then execute
    download_match = re.search(
        r"(?:wget|curl)\s+.*?(?:https?://\S+/(\S+)|(\S+\.\w+))",
        command, re.I
    )
    if download_match:
        filename = (download_match.group(1) or download_match.group(2) or "").lower()
        if any(filename.endswith(ext) for ext in _UPLOADED_FILE_EXTENSIONS):
            return filename
    return None
