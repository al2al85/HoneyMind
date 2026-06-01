import json
from datetime import datetime

from base_honeypot import BaseHoneypot, HoneypotSession
from local_log_utils import local_log_path, write_local_event


class LocalLogTestHoneypot(BaseHoneypot):
    def start(self):
        pass

    def stop(self):
        pass


def test_local_logging_creates_directory_and_writes_jsonl(tmp_path):
    log_dir = tmp_path / "logs"
    config = {"local_logging_enabled": True, "local_log_dir": str(log_dir)}
    event = {"dd-honeypot": True, "session-id": "s1", "command": "whoami"}

    write_local_event(event, config)

    files = list(log_dir.glob("*.jsonl"))
    assert len(files) == 1
    line = files[0].read_text(encoding="utf-8").strip()
    assert json.loads(line) == event


def test_local_logging_preserves_dd_honeypot_marker(tmp_path):
    config = {"local_logging_enabled": True, "local_log_dir": str(tmp_path)}

    write_local_event({"dd-honeypot": True, "type": "ssh"}, config)

    event = json.loads(next(tmp_path.glob("*.jsonl")).read_text(encoding="utf-8"))
    assert event["dd-honeypot"] is True


def test_local_logging_can_be_disabled(tmp_path):
    config = {"local_logging_enabled": False, "local_log_dir": str(tmp_path)}

    write_local_event({"dd-honeypot": True}, config)

    assert not list(tmp_path.glob("*.jsonl"))


def test_malformed_log_event_does_not_crash(tmp_path):
    config = {"local_logging_enabled": True, "local_log_dir": str(tmp_path)}

    write_local_event({"dd-honeypot": True, "bad": object()}, config)

    event = json.loads(next(tmp_path.glob("*.jsonl")).read_text(encoding="utf-8"))
    assert event["dd-honeypot"] is True
    assert "bad" in event


def test_daily_filename_formatting(tmp_path):
    config = {
        "local_log_dir": str(tmp_path),
        "local_log_filename": "dd-honeypot-%Y-%m-%d.jsonl",
        "local_log_rotate_daily": True,
    }

    path = local_log_path(config, now=datetime(2026, 6, 1, 12, 0, 0))

    assert path.name == "dd-honeypot-2026-06-01.jsonl"


def test_base_honeypot_log_data_writes_local_jsonl(tmp_path, capsys):
    hp = LocalLogTestHoneypot(
        config={
            "name": "test",
            "local_logging_enabled": True,
            "local_log_dir": str(tmp_path),
        }
    )

    hp.log_data(HoneypotSession(session_id="session-1"), {"command": "id"})

    stdout_event = json.loads(capsys.readouterr().out.strip())
    file_event = json.loads(next(tmp_path.glob("*.jsonl")).read_text(encoding="utf-8"))
    assert stdout_event["dd-honeypot"] is True
    assert file_event["dd-honeypot"] is True
    assert file_event["session-id"] == "session-1"
    assert file_event["command"] == "id"
