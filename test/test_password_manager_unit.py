import json
import os
from pathlib import Path

import pytest

from honeypots.base_honeypot import HoneypotSession
from core.password_manager import PasswordManager


def make_session():
    return HoneypotSession()


class TestPasswordManagerLogging:
    def test_all_attempts_logged(self, tmp_path):
        config = {
            "password_min_attempts": 3,
            "password_max_attempts": 3,
            "local_log_dir": str(tmp_path),
        }
        pm = PasswordManager(config)
        session = make_session()

        for i in range(3):
            pm.attempt(session, "attacker", "pass", "1.2.3.4")

        log_files = list(tmp_path.glob("*.jsonl"))
        assert log_files, "No compatibility log file created"
        all_lines = []
        for lf in log_files:
            all_lines.extend(json.loads(l) for l in lf.read_text().splitlines() if l.strip())
        assert len(all_lines) == 3
        assert all("session_id" in line for line in all_lines)
        assert all("success" in line for line in all_lines)

    def test_failed_attempts_logged(self, tmp_path):
        config = {
            "password_min_attempts": 5,
            "password_max_attempts": 5,
            "password_early_success_probability": 0,
            "local_log_dir": str(tmp_path),
        }
        pm = PasswordManager(config)
        session = make_session()

        # Only 2 attempts, threshold is 5 — all should fail
        for _ in range(2):
            result = pm.attempt(session, "user", "short", "10.0.0.1")
            assert result is False

        log_files = list(tmp_path.glob("*.jsonl"))
        all_lines = []
        for lf in log_files:
            all_lines.extend(json.loads(l) for l in lf.read_text().splitlines() if l.strip())
        failed = [l for l in all_lines if not l["success"]]
        assert len(failed) == 2

    def test_successful_attempt_logged_as_success(self, tmp_path):
        config = {
            "password_min_attempts": 1,
            "password_max_attempts": 1,
            "local_log_dir": str(tmp_path),
        }
        pm = PasswordManager(config)
        session = make_session()

        result = pm.attempt(session, "admin", "admin", "1.1.1.1")
        assert result is True

        log_files = list(tmp_path.glob("*.jsonl"))
        all_lines = []
        for lf in log_files:
            all_lines.extend(json.loads(l) for l in lf.read_text().splitlines() if l.strip())
        successes = [l for l in all_lines if l["success"]]
        assert len(successes) == 1
        assert successes[0]["password"] == "admin"


class TestPasswordManagerAcceptance:
    def _config(self, **overrides):
        config = {"password_compat_files_enabled": False}
        config.update(overrides)
        return config

    def test_rejects_before_threshold(self):
        pm = PasswordManager(
            self._config(
                password_min_attempts=6,
                password_max_attempts=6,
                password_early_success_probability=0,
            )
        )
        session = make_session()
        for _ in range(5):
            assert pm.attempt(session, "u", "pass", "1.2.3.4") is False

    def test_accepts_at_threshold(self):
        pm = PasswordManager(
            self._config(
                password_min_attempts=6,
                password_max_attempts=6,
                password_early_success_probability=0,
            )
        )
        session = make_session()
        for _ in range(5):
            pm.attempt(session, "u", "pass", "1.2.3.4")
        assert pm.attempt(session, "u", "pass", "1.2.3.4") is True

    def test_rejects_long_password_even_at_threshold(self):
        pm = PasswordManager(
            self._config(
                password_min_attempts=1,
                password_max_attempts=1,
                password_max_length=8,
            )
        )
        session = make_session()
        # Password longer than 8 chars should never be accepted
        assert pm.attempt(session, "u", "toolongpassword", "1.2.3.4") is False

    def test_accepts_password_exactly_8_chars(self):
        pm = PasswordManager(
            self._config(
                password_min_attempts=1,
                password_max_attempts=1,
                password_max_length=8,
            )
        )
        session = make_session()
        assert pm.attempt(session, "u", "12345678", "1.2.3.4") is True

    def test_threshold_range(self):
        """Threshold must be between min and max (inclusive)."""
        results = set()
        for _ in range(50):
            pm = PasswordManager(
                self._config(
                    password_min_attempts=6,
                    password_max_attempts=10,
                    password_early_success_probability=0,
                )
            )
            session = make_session()
            accepted_at = None
            for i in range(1, 15):
                if pm.attempt(session, "u", "pass", f"192.168.0.{i % 254}"):
                    accepted_at = i
                    break
                # Use a fresh per-attempt key so we control the count
                # Actually we need same IP to accumulate — use the same IP
            # Reset and use same IP consistently
            pm2 = PasswordManager(
                self._config(
                    password_min_attempts=6,
                    password_max_attempts=10,
                    password_early_success_probability=0,
                )
            )
            s2 = make_session()
            for j in range(1, 15):
                ok = pm2.attempt(s2, "u", "pass", "fixed_ip")
                if ok:
                    results.add(j)
                    break
        # All observed thresholds should be in [6, 10]
        for t in results:
            assert 6 <= t <= 10, f"Unexpected threshold: {t}"

    def test_ip_based_tracking_across_sessions(self):
        """Attempts from the same IP accumulate across different HoneypotSession objects."""
        pm = PasswordManager(
            self._config(
                password_min_attempts=3,
                password_max_attempts=3,
                password_early_success_probability=0,
            )
        )
        ip = "5.5.5.5"
        s1 = make_session()
        s2 = make_session()
        s3 = make_session()
        assert pm.attempt(s1, "u", "pass", ip) is False  # attempt 1
        assert pm.attempt(s2, "u", "pass", ip) is False  # attempt 2
        assert pm.attempt(s3, "u", "pass", ip) is True   # attempt 3 = threshold

    def test_always_succeeds_after_first_success(self):
        """Once a password succeeds it is added to the allowed set and always works immediately."""
        pm = PasswordManager(
            self._config(password_min_attempts=2, password_max_attempts=2)
        )
        ip = "6.6.6.6"
        s = make_session()
        pm.attempt(s, "u", "pass", ip)
        pm.attempt(s, "u", "pass", ip)  # success → added to _allowed

        # Now always succeeds immediately, regardless of IP or session
        s2 = make_session()
        assert pm.attempt(s2, "u", "pass", "9.9.9.9") is True
    
    def test_resets_after_success(self):
        """After success, the password is permanently allowed and the IP counter resets for new passwords."""
        pm = PasswordManager(
            self._config(
                password_min_attempts=2,
                password_max_attempts=2,
                password_early_success_probability=0,
            )
        )
        ip = "6.6.6.6"
        s = make_session()
        pm.attempt(s, "u", "pass", ip)   # count=1, fail
        pm.attempt(s, "u", "pass", ip)   # count=2 = threshold, success → "pass" added to allowed

        # "pass" is permanently allowed — always succeeds from now on
        s2 = make_session()
        assert pm.attempt(s2, "u", "pass", ip) is True

        # A different password from the same IP starts at count 0 (tracking was reset)
        s3 = make_session()
        assert pm.attempt(s3, "u", "otherpass", ip) is False  # count=1, threshold=2


class TestPasswordManagerSaveSuccessful:
    def test_saves_successful_credential(self, tmp_path):
        config = {
            "password_min_attempts": 1,
            "password_max_attempts": 1,
            "local_log_dir": str(tmp_path),
        }
        pm = PasswordManager(config)
        session = make_session()
        pm.attempt(session, "root", "admin", "9.9.9.9")

        success_file = tmp_path / "successful_passwords.jsonl"
        assert success_file.exists(), "successful_passwords.jsonl not created"
        entry = json.loads(success_file.read_text().strip())
        assert entry["username"] == "root"
        assert entry["password"] == "admin"
        assert entry["client_ip"] == "9.9.9.9"
        assert entry["success"] is True

    def test_does_not_save_failed_credential(self, tmp_path):
        config = {
            "password_min_attempts": 5,
            "password_max_attempts": 5,
            "password_early_success_probability": 0,
            "local_log_dir": str(tmp_path),
        }
        pm = PasswordManager(config)
        session = make_session()
        pm.attempt(session, "root", "pass", "9.9.9.9")  # only 1 attempt, threshold 5

        success_file = tmp_path / "successful_passwords.jsonl"
        assert not success_file.exists()

    def test_saves_multiple_successes(self, tmp_path):
        config = {
            "password_min_attempts": 1,
            "password_max_attempts": 1,
            "local_log_dir": str(tmp_path),
        }
        pm = PasswordManager(config)

        for i in range(3):
            s = make_session()
            pm.attempt(s, f"user{i}", "pass", f"10.0.0.{i + 1}")

        success_file = tmp_path / "successful_passwords.jsonl"
        lines = [json.loads(l) for l in success_file.read_text().splitlines() if l.strip()]
        assert len(lines) == 3
