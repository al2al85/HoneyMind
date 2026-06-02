"""
IP enrichment: geolocation, ASN, anonymization detection.
Uses ip-api.com (free, no key) with SQLite cache.
"""
import ipaddress
import json
import sqlite3
import time
import urllib.request
from pathlib import Path
from typing import Optional

_DEFAULT_CACHE = "/data/honeypot/logs/ip_cache.db"
_API_URL = "http://ip-api.com/json/{}?fields=status,country,countryCode,regionName,city,timezone,isp,org,as,proxy,hosting,query"
_TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"
_CACHE_TTL_SECONDS = 86400 * 7  # 1 week

_KNOWN_VPN_ORGS = {
    "mullvad", "nordvpn", "expressvpn", "protonvpn", "surfshark",
    "cyberghost", "purevpn", "ipvanish", "pia", "private internet access",
    "hide.me", "windscribe", "tunnelbear",
}

_DATACENTER_ORGS = {
    "amazon", "aws", "digitalocean", "linode", "vultr", "hetzner",
    "ovh", "scaleway", "google cloud", "microsoft azure", "cloudflare",
    "leaseweb", "serverius", "choopa", "constant contact",
}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _init_cache(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_cache (
            ip TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            cached_at INTEGER NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tor_exits (
            ip TEXT PRIMARY KEY,
            updated_at INTEGER NOT NULL
        )
    """)
    conn.commit()
    return conn


def _load_tor_exits(conn: sqlite3.Connection) -> set:
    cutoff = int(time.time()) - _CACHE_TTL_SECONDS
    rows = conn.execute(
        "SELECT ip FROM tor_exits WHERE updated_at > ?", (cutoff,)
    ).fetchall()
    if rows:
        return {r[0] for r in rows}

    try:
        with urllib.request.urlopen(_TOR_LIST_URL, timeout=5) as resp:
            ips = {line.strip() for line in resp.read().decode().splitlines()
                   if line.strip() and not line.startswith("#")}
        now = int(time.time())
        conn.execute("DELETE FROM tor_exits")
        conn.executemany(
            "INSERT OR REPLACE INTO tor_exits VALUES (?, ?)",
            [(ip, now) for ip in ips]
        )
        conn.commit()
        return ips
    except Exception:
        return set()


def _classify_anonymization(data: dict, is_tor: bool) -> tuple[str, int]:
    """Returns (anonymization_type, level 1-4)."""
    if is_tor:
        return "tor", 2

    org = (data.get("org") or "").lower()
    isp = (data.get("isp") or "").lower()
    combined = org + " " + isp

    if any(vpn in combined for vpn in _KNOWN_VPN_ORGS):
        return "vpn_commercial", 3

    if data.get("proxy"):
        return "proxy", 2

    if any(dc in combined for dc in _DATACENTER_ORGS) or data.get("hosting"):
        return "datacenter", 1

    return "residential", 4


class IPEnricher:
    def __init__(self, cache_path: str = _DEFAULT_CACHE):
        Path(cache_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = _init_cache(cache_path)
        self._tor_exits = _load_tor_exits(self._conn)

    def enrich(self, ip: str) -> dict:
        if not ip or _is_private(ip):
            return _private_result(ip)

        cached = self._from_cache(ip)
        if cached:
            return cached

        result = self._fetch(ip)
        self._store_cache(ip, result)
        return result

    def _from_cache(self, ip: str) -> Optional[dict]:
        cutoff = int(time.time()) - _CACHE_TTL_SECONDS
        row = self._conn.execute(
            "SELECT data FROM ip_cache WHERE ip = ? AND cached_at > ?",
            (ip, cutoff)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def _store_cache(self, ip: str, data: dict) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO ip_cache VALUES (?, ?, ?)",
            (ip, json.dumps(data), int(time.time()))
        )
        self._conn.commit()

    def _fetch(self, ip: str) -> dict:
        try:
            url = _API_URL.format(ip)
            with urllib.request.urlopen(url, timeout=5) as resp:
                raw = json.loads(resp.read().decode())
        except Exception:
            return _unknown_result(ip)

        if raw.get("status") != "success":
            return _unknown_result(ip)

        is_tor = ip in self._tor_exits
        anon_type, anon_level = _classify_anonymization(raw, is_tor)

        return {
            "ip": ip,
            "country": raw.get("country"),
            "country_code": raw.get("countryCode"),
            "city": raw.get("city"),
            "region": raw.get("regionName"),
            "timezone": raw.get("timezone"),
            "isp": raw.get("isp"),
            "org": raw.get("org"),
            "asn": raw.get("as"),
            "is_tor": is_tor,
            "is_vpn": anon_type == "vpn_commercial",
            "is_proxy": bool(raw.get("proxy")),
            "is_hosting": bool(raw.get("hosting")),
            "is_residential": anon_type == "residential",
            "anonymization_type": anon_type,
            "anonymization_level": anon_level,
        }

    def local_hour(self, ip_data: dict, utc_hour: int) -> Optional[int]:
        tz = ip_data.get("timezone")
        if not tz:
            return None
        try:
            import zoneinfo
            from datetime import datetime, timezone
            utc_dt = datetime.now(timezone.utc).replace(hour=utc_hour)
            local_dt = utc_dt.astimezone(zoneinfo.ZoneInfo(tz))
            return local_dt.hour
        except Exception:
            return None


def _private_result(ip: str) -> dict:
    return {
        "ip": ip, "country": None, "country_code": None,
        "city": None, "region": None, "timezone": None,
        "isp": "private", "org": "private", "asn": None,
        "is_tor": False, "is_vpn": False, "is_proxy": False,
        "is_hosting": False, "is_residential": False,
        "anonymization_type": "private", "anonymization_level": 0,
    }


def _unknown_result(ip: str) -> dict:
    return {
        "ip": ip, "country": None, "country_code": None,
        "city": None, "region": None, "timezone": None,
        "isp": None, "org": None, "asn": None,
        "is_tor": False, "is_vpn": False, "is_proxy": False,
        "is_hosting": False, "is_residential": False,
        "anonymization_type": "unknown", "anonymization_level": 0,
    }


_FLAG_MAP = {
    "FR": "🇫🇷", "DE": "🇩🇪", "US": "🇺🇸", "RU": "🇷🇺", "CN": "🇨🇳",
    "GB": "🇬🇧", "NL": "🇳🇱", "UA": "🇺🇦", "BR": "🇧🇷", "IN": "🇮🇳",
    "KP": "🇰🇵", "IR": "🇮🇷", "RO": "🇷🇴", "PL": "🇵🇱", "SG": "🇸🇬",
}

_ANON_ICONS = {
    "tor": "🧅 Tor",
    "vpn_commercial": "🔒 VPN",
    "proxy": "🔀 Proxy",
    "datacenter": "🖥  Datacenter",
    "residential": "🏠 Résidentiel",
    "private": "🔒 Privé",
    "unknown": "❓",
}


def format_ip_line(data: dict) -> str:
    flag = _FLAG_MAP.get(data.get("country_code") or "", "🌍")
    location = ", ".join(filter(None, [data.get("city"), data.get("country")]))
    asn = data.get("asn") or ""
    anon = _ANON_ICONS.get(data.get("anonymization_type") or "", "")
    level = data.get("anonymization_level") or 0
    parts = [f"{flag} {location}" if location else "localisation inconnue"]
    if asn:
        parts.append(f"({asn})")
    if anon:
        parts.append(f"| {anon} [niveau {level}/4]")
    return "  ".join(parts)
