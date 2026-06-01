import json
import os
from pathlib import Path

import pytest

from base_honeypot import HoneypotSession
from password_manager import PasswordManager


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
        assert log_files, "No log file created"
        lines = [json.loads(l) for l in log_files[0].read_text().splitlines() if l.strip()]
        password_logs = [l for l in lines if l.get("type") == "password_attempt"]
        assert len(password_logs) == 3

    def test_failed_attempts_logged(self, tmp_path):
        config = {
            "password_min_attempts": 5,
            "password_max_attempts": 5,
            "local_log_dir": str(tmp_path),
        }
        pm = PasswordManager(config)
        session = make_session()

        # Only 2 attempts, threshold is 5 — all should fail
        for _ in range(2):
            result = pm.attempt(session, "user", "short", "10.0.0.1")
            assert result is False

        log_files = list(tmp_path.glob("*.jsonl"))
        lines = [json.loads(l) for l in log_files[0].read_text().splitlines() if l.strip()]
        failed = [l for l in lines if l.get("type") == "password_attempt" and not l["success"]]
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
        lines = [json.loads(l) for l in log_files[0].read_text().splitlines() if l.strip()]
        successes = [l for l in lines if l.get("type") == "password_attempt" and l["success"]]
        assert len(successes) == 1
        assert successes[0]["password"] == "admin"


class TestPasswordManagerAcceptance:
    def test_rejects_before_threshold(self):
        pm = PasswordManager({"password_min_attempts": 6, "password_max_attempts": 6})
        session = make_session()
        for _ in range(5):
            assert pm.attempt(session, "u", "pass", "1.2.3.4") is False

    def test_accepts_at_threshold(self):
        pm = PasswordManager({"password_min_attempts": 6, "password_max_attempts": 6})
        session = make_session()
        for _ in range(5):
            pm.attempt(session, "u", "pass", "1.2.3.4")
        assert pm.attempt(session, "u", "pass", "1.2.3.4") is True

    def test_rejects_long_password_even_at_threshold(self):
        pm = PasswordManager(
            {
                "password_min_attempts": 1,
                "password_max_attempts": 1,
                "password_max_length": 8,
            }
        )
        session = make_session()
        # Password longer than 8 chars should never be accepted
        assert pm.attempt(session, "u", "toolongpassword", "1.2.3.4") is False

    def test_accepts_password_exactly_8_chars(self):
        pm = PasswordManager(
            {
                "password_min_attempts": 1,
                "password_max_attempts": 1,
                "password_max_length": 8,
            }
        )
        session = make_session()
        assert pm.attempt(session, "u", "12345678", "1.2.3.4") is True

    def test_threshold_range(self):
        """Threshold must be between min and max (inclusive)."""
        results = set()
        for _ in range(50):
            pm = PasswordManager({"password_min_attempts": 6, "password_max_attempts": 10})
            session = make_session()
            accepted_at = None
            for i in range(1, 15):
                if pm.attempt(session, "u", "pass", f"192.168.0.{i % 254}"):
                    accepted_at = i
                    break
                # Use a fresh per-attempt key so we control the count
                # Actually we need same IP to accumulate — use the same IP
            # Reset and use same IP consistently
            pm2 = PasswordManager({"password_min_attempts": 6, "password_max_attempts": 10})
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
        pm = PasswordManager({"password_min_attempts": 3, "password_max_attempts": 3})
        ip = "5.5.5.5"
        s1 = make_session()
        s2 = make_session()
        s3 = make_session()
        assert pm.attempt(s1, "u", "pass", ip) is False  # attempt 1
        assert pm.attempt(s2, "u", "pass", ip) is False  # attempt 2
        assert pm.attempt(s3, "u", "pass", ip) is True   # attempt 3 = threshold

    def test_resets_after_success(self):
        """After a successful attempt, the counter resets so next attempt starts fresh."""
        pm = PasswordManager({"password_min_attempts": 2, "password_max_attempts": 2})
        ip = "6.6.6.6"
        s = make_session()
        pm.attempt(s, "u", "pass", ip)
        pm.attempt(s, "u", "pass", ip)  # success, resets

        # Counter reset — next attempt should fail again
        s2 = make_session()
        assert pm.attempt(s2, "u", "pass", ip) is False


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

    def test_does_not_save_failed_credential(self, tmp_path):
        config = {
            "password_min_attempts": 5,
            "password_max_attempts": 5,
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
