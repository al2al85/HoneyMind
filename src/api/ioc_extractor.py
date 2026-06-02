"""
Static IOC extraction from honeypot sessions.

Extracts:
  - ipv4-addr  : every IP that initiated a connection
  - url        : URLs used in wget/curl commands
  - domain-name: domains extracted from those URLs
  - file       : SHA-256 of files dropped via wget/curl/scp (if present on disk)

Every IOC carries the list of source IPs and campaign IDs it is linked to,
enabling EDR-side filtering by IP or campaign.
"""
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from analysis.attack_classifier import classify_command
from analysis.campaign_detector import Campaign


@dataclass
class IOC:
    ioc_type: str           # "ipv4-addr" | "url" | "domain-name" | "file"
    value: str
    first_seen: Optional[str]
    last_seen: Optional[str]
    confidence: float       # 0.0–1.0
    attack_categories: list[str]
    source_ips: list[str]
    campaign_ids: list[str]
    session_ids: list[str]
    context: dict = field(default_factory=dict)


URL_RE = re.compile(r'https?://[^\s\'"<>\]]+')
_IP_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


def cmd_str(event: dict) -> Optional[str]:
    cmd = event.get("command")
    if isinstance(cmd, dict):
        return cmd.get("raw") or cmd.get("normalized")
    if isinstance(cmd, str):
        return cmd
    return None


def event_ip(event: dict) -> Optional[str]:
    return (event.get("client") or {}).get("ip") or event.get("client_ip")


def session_ip(events: list[dict]) -> Optional[str]:
    for e in events:
        ip = event_ip(e)
        if ip:
            return ip
    return None


def time_bounds(events: list[dict]) -> tuple[Optional[str], Optional[str]]:
    ts = [e.get("timestamp") or e.get("time") for e in events]
    ts = [t for t in ts if t]
    if not ts:
        return None, None
    return min(ts), max(ts)


def file_sha256(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def domain_from_url(url: str) -> Optional[str]:
    try:
        host = urlparse(url).hostname or ""
        return host if host and not _IP_RE.match(host) else None
    except Exception:
        return None


def filename_from_url(url: str) -> Optional[str]:
    name = os.path.basename(urlparse(url).path)
    return name or None


def row_to_ioc(row: dict) -> IOC:
    """Convert a DB row (from ioc_store.query_iocs) back to an IOC dataclass."""
    return IOC(
        ioc_type=row["ioc_type"],
        value=row["value"],
        first_seen=row.get("first_seen"),
        last_seen=row.get("last_seen"),
        confidence=float(row.get("confidence") or 0),
        attack_categories=row.get("attack_categories") or [],
        source_ips=row.get("source_ips") or [],
        campaign_ids=row.get("campaign_ids") or [],
        session_ids=row.get("session_ids") or [],
        context=row.get("context") or {},
    )


def extract_iocs(
    sessions: dict[str, list[dict]],
    campaigns: list[Campaign],
    download_dir: str = "/data/honeypot/downloads",
    upload_dir: str = "/data/honeypot/uploads",
) -> list[IOC]:
    """Batch extraction — kept for tests and one-off analysis."""
    ip_to_camps: dict[str, list[str]] = {}
    for camp in campaigns:
        for ip in camp.ips:
            ip_to_camps.setdefault(ip, []).append(camp.campaign_id)

    registry: dict[tuple[str, str], IOC] = {}

    def _upsert(ioc: IOC) -> None:
        key = (ioc.ioc_type, ioc.value)
        if key not in registry:
            registry[key] = ioc
            return
        ex = registry[key]
        ts = [t for t in [ex.first_seen, ioc.first_seen] if t]
        ex.first_seen = min(ts) if ts else None
        ts = [t for t in [ex.last_seen, ioc.last_seen] if t]
        ex.last_seen = max(ts) if ts else None
        ex.confidence = max(ex.confidence, ioc.confidence)
        for lst_ex, lst_new in [
            (ex.campaign_ids, ioc.campaign_ids),
            (ex.source_ips, ioc.source_ips),
            (ex.session_ids, ioc.session_ids),
            (ex.attack_categories, ioc.attack_categories),
        ]:
            for v in lst_new:
                if v not in lst_ex:
                    lst_ex.append(v)
        ex.context.update(ioc.context)

    for sid, events in sessions.items():
        ip = session_ip(events)
        if not ip:
            continue

        camp_ids = ip_to_camps.get(ip, [])
        first_seen, last_seen = time_bounds(events)

        _upsert(IOC(
            ioc_type="ipv4-addr",
            value=ip,
            first_seen=first_seen,
            last_seen=last_seen,
            confidence=0.95,
            attack_categories=[],
            source_ips=[ip],
            campaign_ids=camp_ids[:],
            session_ids=[sid],
        ))

        session_cats: set[str] = set()

        for event in events:
            cmd = cmd_str(event)
            if not cmd:
                _process_scp_event(event, ip, camp_ids, sid, upload_dir, _upsert)
                continue

            cat = classify_command(cmd)
            cat_val = cat.value
            if cat_val != "UNKNOWN":
                session_cats.add(cat_val)

            ts = event.get("timestamp") or event.get("time")

            if re.search(r'\b(wget|curl)\b', cmd):
                for url in URL_RE.findall(cmd):
                    _upsert(IOC(
                        ioc_type="url",
                        value=url,
                        first_seen=ts, last_seen=ts,
                        confidence=0.90,
                        attack_categories=[cat_val],
                        source_ips=[ip],
                        campaign_ids=camp_ids[:],
                        session_ids=[sid],
                        context={"command": cmd},
                    ))
                    domain = domain_from_url(url)
                    if domain:
                        _upsert(IOC(
                            ioc_type="domain-name",
                            value=domain,
                            first_seen=ts, last_seen=ts,
                            confidence=0.85,
                            attack_categories=[cat_val],
                            source_ips=[ip],
                            campaign_ids=camp_ids[:],
                            session_ids=[sid],
                            context={"source_url": url},
                        ))
                    fname = filename_from_url(url)
                    if fname:
                        digest = file_sha256(os.path.join(download_dir, fname))
                        if digest:
                            _upsert(IOC(
                                ioc_type="file",
                                value=digest,
                                first_seen=ts, last_seen=ts,
                                confidence=0.98,
                                attack_categories=[cat_val],
                                source_ips=[ip],
                                campaign_ids=camp_ids[:],
                                session_ids=[sid],
                                context={
                                    "filename": fname,
                                    "sha256": digest,
                                    "source_url": url,
                                    "transfer_method": "wget/curl",
                                },
                            ))

        ip_key = ("ipv4-addr", ip)
        for cat in session_cats:
            if cat not in registry[ip_key].attack_categories:
                registry[ip_key].attack_categories.append(cat)

    return list(registry.values())


def _process_scp_event(event, ip, camp_ids, sid, upload_dir, upsert):
    details = event.get("details") or {}
    if details.get("event") != "scp_upload":
        return
    filename = details.get("filename")
    if not filename:
        return
    digest = file_sha256(os.path.join(upload_dir, os.path.basename(filename)))
    if not digest:
        return
    ts = event.get("timestamp") or event.get("time")
    upsert(IOC(
        ioc_type="file",
        value=digest,
        first_seen=ts, last_seen=ts,
        confidence=0.99,
        attack_categories=["LATERAL_MOVEMENT"],
        source_ips=[ip],
        campaign_ids=camp_ids[:],
        session_ids=[sid],
        context={
            "filename": os.path.basename(filename),
            "sha256": digest,
            "transfer_method": "scp",
        },
    ))
