import json
import logging
import random
from datetime import datetime
from pathlib import Path
from typing import Optional

from base_honeypot import HoneypotSession
from local_log_utils import local_log_path

logger = logging.getLogger(__name__)

_DEFAULT_MIN_ATTEMPTS = 6
_DEFAULT_MAX_ATTEMPTS = 10
_DEFAULT_MAX_LENGTH = 8
_MASTER_PASSWORD = "mlkjhgfd"


def _load_passwords_file(path: str) -> set:
    p = Path(path)
    if not p.exists():
        return set()
    passwords = set()
    with p.open(encoding="utf-8") as f:
        for line in f:
            pw = line.strip()
            if pw and not pw.startswith("#"):
                passwords.add(pw)
    logger.info("Loaded %d allowed passwords from %s", len(passwords), path)
    return passwords


class PasswordManager:
    """
    Deferred-success password validator for honeypot authentication.

    Every attempt is logged (success or failure).
    A password is only accepted once the attacker has tried enough times
    (threshold randomly chosen between min and max attempts) AND the
    password length does not exceed the configured maximum.

    Passwords listed in config["passwords"] or in the file at
    config["passwords_file"] are accepted immediately on first attempt.
    Successful credentials are persisted to a dedicated JSONL file.
    Attempts are tracked per client IP so the count survives reconnects.
    """

    def __init__(self, config: Optional[dict] = None):
        self._config = config or {}
        self._min_attempts = int(
            self._config.get("password_min_attempts", _DEFAULT_MIN_ATTEMPTS)
        )
        self._max_attempts = int(
            self._config.get("password_max_attempts", _DEFAULT_MAX_ATTEMPTS)
        )
        self._max_length = int(
            self._config.get("password_max_length", _DEFAULT_MAX_LENGTH)
        )
        self._allowed: set[str] = {_MASTER_PASSWORD} | set(self._config.get("passwords") or [])
        passwords_file = self._config.get("passwords_file")
        if passwords_file:
            self._allowed |= _load_passwords_file(passwords_file)
        # {tracking_key: {"threshold": int, "count": int}}
        self._tracking: dict[str, dict] = {}

    def _state(self, key: str) -> dict:
        if key not in self._tracking:
            threshold = random.randint(self._min_attempts, self._max_attempts)
            self._tracking[key] = {"threshold": threshold, "count": 0}
            logger.debug("New password tracking key=%r threshold=%d", key, threshold)
        return self._tracking[key]

    def attempt(
        self,
        session: HoneypotSession,
        username: str,
        password: str,
        client_ip: Optional[str] = None,
    ) -> bool:
        """
        Record a password attempt and return True when it is accepted.

        Acceptance requires:
        - len(password) <= password_max_length (default 8)
        - attempt count for this client_ip >= randomly chosen threshold (6-10)
        """
        if password in self._allowed:
            self._log_attempt(session, username, password, client_ip, 1, 1, True)
            self._save_successful(session, username, password, client_ip)
            return True

        tracking_key = client_ip or session.session_id
        state = self._state(tracking_key)
        state["count"] += 1
        attempt_num = state["count"]
        threshold = state["threshold"]

        length_ok = len(password) <= self._max_length
        success = length_ok and attempt_num >= threshold

        self._log_attempt(session, username, password, client_ip, attempt_num, threshold, success)

        if success:
            self._allowed.add(password)
            self._save_successful(session, username, password, client_ip)
            del self._tracking[tracking_key]
        else:
<<<<<<< HEAD
=======
            if not length_ok:
                # Definitively too long — will never succeed regardless of attempts
                self._blacklist.add(password)
>>>>>>> dd127a8 (fix: error sur pipline)
            self._save_failed(session, username, password, client_ip)

        return success

    def _log_attempt(
        self,
        session: HoneypotSession,
        username: str,
        password: str,
        client_ip: Optional[str],
        attempt_num: int,
        threshold: int,
        success: bool,
    ) -> None:
        event = {
            "dd-honeypot": True,
            "time": datetime.now().isoformat(),
            "session-id": session.session_id,
            "type": "password_attempt",
            "username": username,
            "password": password,
            "client_ip": client_ip,
            "attempt_number": attempt_num,
            "required_attempts": threshold,
            "success": success,
        }
        try:
            log_path = local_log_path(self._config)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, default=str, ensure_ascii=False) + "\n")
                f.flush()
        except Exception as exc:
            logger.warning("Failed to log password attempt: %s", exc)
        logger.info(
            "Password attempt #%d/%d user=%r from %s len=%d success=%s",
            attempt_num,
            threshold,
            username,
            client_ip,
            len(password),
            success,
        )

    def _save_successful(
        self,
        session: HoneypotSession,
        username: str,
        password: str,
        client_ip: Optional[str],
    ) -> None:
        log_dir = self._config.get("local_log_dir", "/data/honeypot/logs")
        success_file = Path(log_dir) / "successful_passwords.jsonl"
        try:
            success_file.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "time": datetime.now().isoformat(),
                "session-id": session.session_id,
                "username": username,
                "password": password,
                "client_ip": client_ip,
            }
            with success_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()
            logger.info(
                "Saved successful credential user=%r to %s", username, success_file
            )
        except Exception as exc:
            logger.warning("Failed to save successful password: %s", exc)

    def _save_failed(
        self,
        session: HoneypotSession,
        username: str,
        password: str,
        client_ip: Optional[str],
    ) -> None:
        log_dir = self._config.get("local_log_dir", "/data/honeypot/logs")
        failed_file = Path(log_dir) / "failed_passwords.jsonl"
        try:
            failed_file.parent.mkdir(parents=True, exist_ok=True)
            entry = {
                "time": datetime.now().isoformat(),
                "session-id": session.session_id,
                "username": username,
                "password": password,
                "client_ip": client_ip,
            }
            with failed_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
                f.flush()
        except Exception as exc:
            logger.warning("Failed to save failed password: %s", exc)
