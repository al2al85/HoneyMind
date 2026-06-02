"""
SSH client fingerprinting: banner + HASSH.

HASSH (SSH client fingerprint) = MD5 of:
  kex_algorithms;encryption_c2s;mac_c2s;compression_c2s

Captured by intercepting the client's KexInit message before negotiation.
"""
import hashlib
import logging
from typing import Optional

import paramiko
from paramiko import Transport

logger = logging.getLogger(__name__)

# Known SSH client signatures from remote_version string
_KNOWN_CLIENTS = {
    "openssh":     "OpenSSH",
    "paramiko":    "Paramiko (Python)",
    "libssh":      "libssh",
    "libssh2":     "libssh2",
    "putty":       "PuTTY",
    "dropbear":    "Dropbear",
    "bitvise":     "Bitvise",
    "jsch":        "JSch (Java)",
    "netsarang":   "NetSarang",
    "winscp":      "WinSCP",
    "cyberduck":   "Cyberduck",
    "filezilla":   "FileZilla",
    "asyncssh":    "AsyncSSH (Python)",
    "twisted":     "Twisted (Python)",
    "fabric":      "Fabric (Python)",
}


def identify_client(remote_version: Optional[str]) -> str:
    """Return a human-readable client name from the SSH version string."""
    if not remote_version:
        return "unknown"
    rv = remote_version.lower()
    for key, label in _KNOWN_CLIENTS.items():
        if key in rv:
            return label
    return remote_version


class FingerprintingTransport(Transport):
    """
    Paramiko Transport subclass that captures the client's KexInit
    algorithms before negotiation, enabling true HASSH computation.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._client_kex_init: Optional[dict] = None

    def _parse_kex_init(self, msg):
        try:
            # Save current position to rewind after reading
            saved = msg.get_so_far()
            msg.rewind()

            # Skip cookie (16 bytes)
            msg.get_bytes(16)

            kex_algos         = msg.get_list()
            _host_key_algos   = msg.get_list()
            enc_c2s           = msg.get_list()
            enc_s2c           = msg.get_list()
            mac_c2s           = msg.get_list()
            mac_s2c           = msg.get_list()
            comp_c2s          = msg.get_list()
            comp_s2c          = msg.get_list()

            self._client_kex_init = {
                "kex_algorithms":              kex_algos,
                "encryption_client_to_server": enc_c2s,
                "mac_client_to_server":        mac_c2s,
                "compression_client_to_server": comp_c2s,
            }

            # Rewind so the original method can re-parse
            msg.rewind()
        except Exception as e:
            logger.debug("HASSH capture failed: %s", e)

        return super()._parse_kex_init(msg)

    def hassh(self) -> Optional[str]:
        """Compute HASSH from the client's proposed algorithms."""
        if not self._client_kex_init:
            return None
        try:
            parts = [
                ",".join(self._client_kex_init.get("kex_algorithms", [])),
                ",".join(self._client_kex_init.get("encryption_client_to_server", [])),
                ",".join(self._client_kex_init.get("mac_client_to_server", [])),
                ",".join(self._client_kex_init.get("compression_client_to_server", [])),
            ]
            raw = ";".join(parts)
            return hashlib.md5(raw.encode()).hexdigest()
        except Exception:
            return None

    def client_fingerprint(self) -> dict:
        """Return a complete fingerprint dict for logging."""
        banner = getattr(self, "remote_version", None)
        return {
            "client_banner": banner,
            "client_name":   identify_client(banner),
            "hassh":         self.hassh(),
            "hassh_algos":   self._client_kex_init,
        }
