"""
Campaign detection: clusters sessions by subnet/ASN/timing/commands/fingerprint.
"""
import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from session_fingerprint import fingerprint_session, identify_user_agent


@dataclass
class Campaign:
    campaign_id: str
    ips: list[str]
    subnet: Optional[str]
    asn: Optional[str]
    time_start: Optional[str]
    time_end: Optional[str]
    session_count: int
    shared_commands: list[str]
    verdict: str   # "coordinated" | "same_tool" | "coincidence"
    confidence: float


def _subnet24(ip: str) -> Optional[str]:
    try:
        net = ipaddress.ip_network(ip + "/24", strict=False)
        return str(net)
    except ValueError:
        return None


def _extract_ip(events: list[dict]) -> Optional[str]:
    for e in events:
        ip = e.get("client_ip") or (e.get("client") or {}).get("ip")
        if ip:
            return ip
    return None


def _extract_time(events: list[dict], first: bool = True) -> Optional[str]:
    times = [e.get("time") or e.get("timestamp") for e in events if e.get("time") or e.get("timestamp")]
    if not times:
        return None
    return min(times) if first else max(times)


def _extract_commands(events: list[dict]) -> set[str]:
    cmds = set()
    for e in events:
        cmd = e.get("command")
        if isinstance(cmd, dict):
            raw = cmd.get("raw") or cmd.get("normalized")
            if raw:
                cmds.add(raw.strip())
        elif isinstance(cmd, str):
            cmds.add(cmd.strip())
        q = e.get("query")
        if isinstance(q, str):
            cmds.add(q.strip())
    return cmds


def _extract_asn(ip_cache: dict, ip: str) -> Optional[str]:
    data = ip_cache.get(ip) or {}
    asn = data.get("asn")
    return asn.split()[0] if asn else None


def _extract_ssh_fingerprint(events: list[dict]) -> Optional[dict]:
    for e in events:
        fp = e.get("ssh_fingerprint")
        if isinstance(fp, dict) and fp.get("hassh"):
            return fp
    return None


def detect_campaigns(
    sessions: dict[str, list[dict]],
    ip_cache: Optional[dict] = None,
    time_window_minutes: int = 60,
) -> list[Campaign]:
    """
    sessions: {session_id: [events]}
    ip_cache: {ip: ip_enricher result}
    """
    ip_cache = ip_cache or {}

    # Build session metadata
    meta = {}
    for sid, events in sessions.items():
        ip = _extract_ip(events)
        if not ip:
            continue
        fp = _extract_ssh_fingerprint(events)
        hassh = fp.get("hassh") if fp else None
        sfp = fingerprint_session(events, hassh=hassh)
        meta[sid] = {
            "ip": ip,
            "subnet24": _subnet24(ip),
            "asn": _extract_asn(ip_cache, ip),
            "time_start": _extract_time(events, first=True),
            "time_end": _extract_time(events, first=False),
            "commands": _extract_commands(events),
            "hassh": hassh,
            "client_banner": fp.get("client_banner") if fp else None,
            "client_name": fp.get("client_name") if fp else None,
            "seq_hash": sfp.get("seq_hash"),
            "tool_match": sfp.get("tool_match"),
            "user_agent": sfp.get("user_agent"),
            "ua_tool": sfp.get("ua_tool"),
        }

    # Group by /24 subnet
    subnet_groups: dict[str, list[str]] = defaultdict(list)
    for sid, m in meta.items():
        if m["subnet24"]:
            subnet_groups[m["subnet24"]].append(sid)

    # Group by HASSH (même outil SSH = même campagne probable)
    hassh_groups: dict[str, list[str]] = defaultdict(list)
    for sid, m in meta.items():
        if m["hassh"]:
            hassh_groups[m["hassh"]].append(sid)

    # Group by sequence hash (même comportement = même outil/script)
    seq_groups: dict[str, list[str]] = defaultdict(list)
    for sid, m in meta.items():
        if m["seq_hash"]:
            seq_groups[m["seq_hash"]].append(sid)

    # Group by User-Agent tool (même scanner HTTP)
    ua_groups: dict[str, list[str]] = defaultdict(list)
    for sid, m in meta.items():
        if m["ua_tool"]:
            ua_groups[m["ua_tool"]].append(sid)

    # Group by ASN
    asn_groups: dict[str, list[str]] = defaultdict(list)
    for sid, m in meta.items():
        if m["asn"]:
            asn_groups[m["asn"]].append(sid)

    campaigns = []
    seen = set()
    campaign_idx = 1

    def _make_campaign(group: list[str], subnet: Optional[str], asn: Optional[str]) -> Campaign:
        nonlocal campaign_idx
        ips = list({meta[s]["ip"] for s in group})
        all_commands = [meta[s]["commands"] for s in group]
        shared = set.intersection(*all_commands) if all_commands else set()
        shared_list = sorted(shared - {""})[:10]

        times_start = [meta[s]["time_start"] for s in group if meta[s]["time_start"]]
        times_end = [meta[s]["time_end"] for s in group if meta[s]["time_end"]]

        if len(ips) >= 3 and shared_list:
            verdict, confidence = "coordinated", 0.85
        elif len(ips) >= 2 and shared_list:
            verdict, confidence = "same_tool", 0.65
        else:
            verdict, confidence = "coincidence", 0.30

        cid = f"C{campaign_idx:03d}"
        campaign_idx += 1
        return Campaign(
            campaign_id=cid,
            ips=ips,
            subnet=subnet,
            asn=asn,
            time_start=min(times_start) if times_start else None,
            time_end=max(times_end) if times_end else None,
            session_count=len(group),
            shared_commands=shared_list,
            verdict=verdict,
            confidence=confidence,
        )

    # Subnet-based clustering (strongest signal)
    for subnet, sids in subnet_groups.items():
        if len(sids) >= 2:
            key = frozenset(sids)
            if key not in seen:
                seen.add(key)
                asn = meta[sids[0]]["asn"]
                campaigns.append(_make_campaign(sids, subnet, asn))

    # HASSH-based clustering (même outil, IPs différentes = campagne distribuée)
    for hassh, sids in hassh_groups.items():
        if len(sids) >= 2:
            key = frozenset(sids)
            if key not in seen:
                seen.add(key)
                asn = meta[sids[0]]["asn"]
                c = _make_campaign(sids, None, asn)
                client_name = meta[sids[0]].get("client_name") or "unknown"
                c.shared_commands = [f"[HASSH:{hassh[:8]}] {client_name}"] + c.shared_commands
                c.verdict = "same_tool"
                campaigns.append(c)

    # Sequence hash clustering (même script, IPs quelconques)
    for seq, sids in seq_groups.items():
        if len(sids) >= 2:
            key = frozenset(sids)
            if key not in seen:
                seen.add(key)
                c = _make_campaign(sids, None, meta[sids[0]]["asn"])
                tool = meta[sids[0]].get("tool_match") or f"seq:{seq[:8]}"
                c.shared_commands = [f"[SEQ:{seq[:8]}] {tool}"] + c.shared_commands
                c.verdict = "same_tool"
                campaigns.append(c)

    # User-Agent clustering (même scanner HTTP)
    for ua_tool, sids in ua_groups.items():
        if len(sids) >= 2:
            key = frozenset(sids)
            if key not in seen:
                seen.add(key)
                c = _make_campaign(sids, None, meta[sids[0]]["asn"])
                c.shared_commands = [f"[UA] {ua_tool}"] + c.shared_commands
                c.verdict = "same_tool"
                campaigns.append(c)

    # ASN-based clustering (broader signal)
    for asn, sids in asn_groups.items():
        if len(sids) >= 3:
            key = frozenset(sids)
            if key not in seen:
                seen.add(key)
                campaigns.append(_make_campaign(sids, None, asn))

    return sorted(campaigns, key=lambda c: -c.confidence)


_VERDICT_ICONS = {
    "coordinated": "🚨 CAMPAGNE COORDONNÉE",
    "same_tool":   "🔧 MÊME OUTIL/FRAMEWORK",
    "coincidence": "🔍 Coïncidence probable",
}


def format_campaign(c: Campaign) -> str:
    icon = _VERDICT_ICONS.get(c.verdict, c.verdict)
    pct = int(c.confidence * 100)
    lines = [
        f"  {icon} [{c.campaign_id}] ({pct}%)",
        f"    IPs : {', '.join(c.ips[:5])}{'...' if len(c.ips) > 5 else ''}",
    ]
    if c.subnet:
        lines.append(f"    Subnet : {c.subnet}")
    if c.asn:
        lines.append(f"    ASN    : {c.asn}")
    if c.time_start:
        lines.append(f"    Fenêtre: {c.time_start[:19]} → {(c.time_end or '')[:19]}")
    if c.shared_commands:
        lines.append(f"    Commandes partagées: {', '.join(c.shared_commands[:5])}")
    return "\n".join(lines)
