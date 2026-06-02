"""
STIX 2.1 serialization for HoneyMind IOCs.

Produces valid STIX 2.1 bundles with:
  - indicator objects (one per IOC)
  - x_honeymind_* custom properties for campaign/IP linkage
  - an identity object identifying the producer
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from api.ioc_extractor import IOC


def _now_stix() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _stix_id(obj_type: str) -> str:
    return f"{obj_type}--{uuid.uuid4()}"


_HONEYMIND_IDENTITY_ID = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, 'honeymind.honeypot')}"

HONEYMIND_IDENTITY = {
    "type": "identity",
    "spec_version": "2.1",
    "id": _HONEYMIND_IDENTITY_ID,
    "created": "2024-01-01T00:00:00Z",
    "modified": "2024-01-01T00:00:00Z",
    "name": "HoneyMind",
    "identity_class": "system",
    "description": "HoneyMind honeypot threat intelligence feed",
}


def _stix_pattern(ioc: IOC) -> Optional[str]:
    v = ioc.value.replace("'", "\\'")
    if ioc.ioc_type == "ipv4-addr":
        return f"[ipv4-addr:value = '{v}']"
    if ioc.ioc_type == "url":
        return f"[url:value = '{v}']"
    if ioc.ioc_type == "domain-name":
        return f"[domain-name:value = '{v}']"
    if ioc.ioc_type == "file":
        return f"[file:hashes.'SHA-256' = '{v}']"
    return None


def _indicator_types(ioc: IOC) -> list[str]:
    cats = set(ioc.attack_categories)
    types = {"malicious-activity"}
    if ioc.ioc_type == "file" or "EXFILTRATION" in cats:
        types.add("malware")
    if ioc.ioc_type in ("url", "domain-name"):
        types.add("malicious-activity")
    return sorted(types)


def _name(ioc: IOC) -> str:
    if ioc.ioc_type == "ipv4-addr":
        return f"Attacker IP: {ioc.value}"
    if ioc.ioc_type == "url":
        return f"Malicious URL: {ioc.value}"
    if ioc.ioc_type == "domain-name":
        return f"Malicious domain: {ioc.value}"
    if ioc.ioc_type == "file":
        filename = ioc.context.get("filename", "unknown")
        method = ioc.context.get("transfer_method", "download")
        return f"Dropped file ({method}): {filename}"
    return ioc.value


def _description(ioc: IOC) -> str:
    parts = ["Observed by HoneyMind honeypot."]
    if ioc.attack_categories:
        parts.append(f"Attack categories: {', '.join(sorted(ioc.attack_categories))}.")
    if ioc.campaign_ids:
        parts.append(f"Campaigns: {', '.join(ioc.campaign_ids)}.")
    if ioc.context.get("source_url"):
        parts.append(f"Source URL: {ioc.context['source_url']}.")
    if ioc.context.get("transfer_method"):
        parts.append(f"Transfer method: {ioc.context['transfer_method']}.")
    return " ".join(parts)


def ioc_to_indicator(ioc: IOC) -> Optional[dict]:
    pattern = _stix_pattern(ioc)
    if not pattern:
        return None

    now = _now_stix()
    labels = ["honeypot"] + [c.lower().replace("_", "-") for c in sorted(ioc.attack_categories)]

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _stix_id("indicator"),
        "created": now,
        "modified": now,
        "created_by_ref": _HONEYMIND_IDENTITY_ID,
        "name": _name(ioc),
        "description": _description(ioc),
        "indicator_types": _indicator_types(ioc),
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ioc.first_seen or now,
        "confidence": int(ioc.confidence * 100),
        "labels": labels,
        # Custom HoneyMind properties for EDR-side correlation
        "x_honeymind_ioc_type": ioc.ioc_type,
        "x_honeymind_source_ips": ioc.source_ips,
        "x_honeymind_campaign_ids": ioc.campaign_ids,
        "x_honeymind_session_ids": ioc.session_ids[:20],
        "x_honeymind_first_seen": ioc.first_seen,
        "x_honeymind_last_seen": ioc.last_seen,
        "x_honeymind_context": ioc.context,
    }


def build_bundle(iocs: list[IOC]) -> dict:
    objects = [HONEYMIND_IDENTITY]
    for ioc in iocs:
        obj = ioc_to_indicator(ioc)
        if obj:
            objects.append(obj)
    return {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "spec_version": "2.1",
        "objects": objects,
    }
