from analysis.campaign_detector import detect_campaigns


def _ssh_session(ip, timestamp, hassh, commands):
    events = [{
        "client_ip": ip,
        "timestamp": timestamp,
        "ssh_fingerprint": {
            "hassh": hassh,
            "client_name": "Paramiko",
        },
    }]
    events.extend(
        {"client_ip": ip, "timestamp": timestamp, "command": command}
        for command in commands
    )
    return events


def test_overlapping_campaign_signals_are_consolidated():
    hassh = "4e0672c5bbb00a3fd45ada0e9e2ed944"
    sessions = {
        "s1": _ssh_session("10.0.0.10", "2026-06-01T10:00:00Z", hassh, ["whoami", "id", "uname -a"]),
        "s2": _ssh_session("10.0.0.11", "2026-06-01T10:01:00Z", hassh, ["whoami", "id", "uname -a"]),
        "s3": _ssh_session("203.0.113.8", "2026-06-01T10:02:00Z", hassh, ["whoami", "id", "uname -a"]),
    }

    campaigns = detect_campaigns(sessions)

    assert len(campaigns) == 1
    assert campaigns[0].session_count == 3
    assert campaigns[0].ips == ["10.0.0.10", "10.0.0.11", "203.0.113.8"]
