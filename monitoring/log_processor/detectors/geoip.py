"""GeoIP and network attribution via ip-api.com (free, no key)."""
import logging
import threading
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

_CACHE: dict[str, dict] = {}
_CACHE_LOCK = threading.Lock()
_LAST_REQUEST: float = 0.0
_RATE_LIMIT_S = 1.5  # ip-api.com free: 45 req/min

_PRIVATE_RANGES = [
    "127.", "10.", "192.168.", "172.16.", "172.17.",
    "172.18.", "172.19.", "172.2", "172.3",
    "::1", "fc", "fd",
]

# Known Tor exit node list URL (optional enrichment)
_TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
_tor_exits: set[str] = set()
_tor_loaded = False
_tor_lock = threading.Lock()


def _is_private(ip: str) -> bool:
    return any(ip.startswith(prefix) for prefix in _PRIVATE_RANGES)


def _load_tor_exits() -> None:
    global _tor_exits, _tor_loaded
    with _tor_lock:
        if _tor_loaded:
            return
        try:
            r = requests.get(_TOR_EXIT_URL, timeout=10)
            if r.ok:
                _tor_exits = {line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith("#")}
                logger.info(f"Loaded {len(_tor_exits)} Tor exit nodes")
        except Exception as e:
            logger.warning(f"Could not load Tor exit list: {e}")
        finally:
            _tor_loaded = True


def lookup(ip: str) -> dict:
    """Return geo/network info for an IP. Returns empty dict on failure."""
    if not ip or ip == "?" or _is_private(ip):
        return {"country": "private", "country_code": "LO", "is_private": True}

    with _CACHE_LOCK:
        if ip in _CACHE:
            return _CACHE[ip]

    global _LAST_REQUEST
    now = time.time()
    wait = _RATE_LIMIT_S - (now - _LAST_REQUEST)
    if wait > 0:
        time.sleep(wait)

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,regionName,city,isp,org,as,proxy,hosting"},
            timeout=5,
        )
        _LAST_REQUEST = time.time()

        if resp.ok:
            data = resp.json()
            if data.get("status") == "success":
                result = {
                    "country": data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "isp": data.get("isp", ""),
                    "org": data.get("org", ""),
                    "asn": data.get("as", ""),
                    "is_proxy": data.get("proxy", False),
                    "is_hosting": data.get("hosting", False),
                    "is_private": False,
                }
                # Check Tor
                if not _tor_loaded:
                    threading.Thread(target=_load_tor_exits, daemon=True).start()
                result["is_tor"] = ip in _tor_exits

                with _CACHE_LOCK:
                    _CACHE[ip] = result
                return result
    except Exception as e:
        logger.debug(f"GeoIP lookup failed for {ip}: {e}")

    fallback = {"country": "", "country_code": "", "is_private": False, "is_tor": False}
    with _CACHE_LOCK:
        _CACHE[ip] = fallback
    return fallback
