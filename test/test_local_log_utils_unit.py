import json
from datetime import datetime

from honeypots.base_honeypot import BaseHoneypot, HoneypotSession
from logging_pipeline.canonical_log_utils import build_event, client_identity
from logging_pipeline.local_log_utils import local_log_path, write_local_event


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
    assert stdout_event["schema_version"] == 1
    assert file_event["schema_version"] == 1
    assert file_event["session_id"] == "session-1"
    assert file_event["event_type"] == "command"
    assert file_event["command"]["raw"] == "id"


def test_base_honeypot_log_data_adds_normalized_command(tmp_path, capsys):
    hp = LocalLogTestHoneypot(
        config={
            "name": "test",
            "local_logging_enabled": True,
            "local_log_dir": str(tmp_path),
        }
    )

    hp.log_data(HoneypotSession(session_id="session-1"), {"command": "ls     Doc"})

    stdout_event = json.loads(capsys.readouterr().out.strip())
    assert stdout_event["event_type"] == "command"
    assert stdout_event["command"]["raw"] == "ls     Doc"
    assert stdout_event["command"]["normalized"] == "ls Doc"
    assert "raw_input" not in stdout_event
    assert "normalized_input" not in stdout_event


def test_base_honeypot_normalized_logging_can_be_disabled(tmp_path, capsys):
    hp = LocalLogTestHoneypot(
        config={
            "name": "test",
            "local_logging_enabled": True,
            "local_log_dir": str(tmp_path),
            "log_normalized_input": False,
        }
    )

    hp.log_data(HoneypotSession(session_id="session-1"), {"command": "ls     Doc"})

    stdout_event = json.loads(capsys.readouterr().out.strip())
    assert stdout_event["command"]["raw"] == "ls     Doc"
    assert stdout_event["command"]["normalized"] == "ls Doc"
    assert "normalized_command" not in stdout_event
    assert "normalized_input" not in stdout_event


def test_canonical_event_has_required_fields_and_nested_client():
    session = HoneypotSession(session_id="session-1")
    event = build_event(
        session=session,
        event_type="auth_attempt",
        service="ssh",
        config={"name": "Alpine Linux", "profile": "alpine-linux"},
        port=2222,
        client=client_identity(ip="1.2.3.4", username="root"),
        auth={
            "method": "password",
            "password": "toor",
            "attempt_number": 1,
            "required_attempts": 3,
            "success": False,
        },
    )

    for key in (
        "schema_version",
        "timestamp",
        "event_id",
        "session_id",
        "seq",
        "event_type",
        "service",
    ):
        assert key in event
    assert event["seq"] == 1
    assert event["client"] == {"ip": "1.2.3.4", "username": "root"}
    assert event["auth"]["success"] is False
    assert "username" not in event
    assert "password" not in event
    assert "success" not in event


def test_canonical_seq_increases_monotonically():
    session = HoneypotSession(session_id="session-1")
    first = build_event(session=session, event_type="session_start", service="ssh")
    second = build_event(session=session, event_type="session_end", service="ssh")
    assert [first["seq"], second["seq"]] == [1, 2]


def test_canonical_ssh_logger_writes_complete_session(tmp_path, capsys):
    hp = LocalLogTestHoneypot(
        port=2222,
        config={
            "name": "Alpine Linux",
            "profile": "alpine-linux",
            "local_logging_enabled": True,
            "local_log_dir": str(tmp_path),
        },
    )
    session = HoneypotSession(session_id="session-1")

    hp.log_session_start(session, client_ip="1.2.3.4")
    hp.log_auth_attempt(
        session,
        username="root",
        password="toor",
        client_ip="1.2.3.4",
        attempt_number=1,
        required_attempts=3,
        success=False,
    )
    hp.log_command(
        session,
        raw="uname      -a",
        response="Linux alpine-vm 6.1.21 x86_64 GNU/Linux\n",
        parser_action="hardcoded",
        exit_code=0,
    )
    hp.log_session_end(session, client_ip="1.2.3.4", close_reason="closed")

    capsys.readouterr()
    lines = [
        json.loads(line)
        for line in next(tmp_path.glob("*.jsonl")).read_text(encoding="utf-8").splitlines()
    ]
    assert [event["seq"] for event in lines] == [1, 2, 3, 4]
    assert [event["event_type"] for event in lines] == [
        "session_start",
        "auth_attempt",
        "command",
        "session_end",
    ]
    auth_event = lines[1]
    assert "auth" in auth_event
    assert not {"username", "password", "success"} & set(auth_event)
    command_event = lines[2]
    assert command_event["command"]["raw"] == "uname      -a"
    assert command_event["command"]["normalized"] == "uname -a"
    assert command_event["command"]["parser_action"] == "hardcoded"
    assert "Linux alpine-vm" in command_event["command"]["response"]
    assert lines[3]["details"]["auth_attempts"] == 1
    assert lines[3]["details"]["commands"] == 1
