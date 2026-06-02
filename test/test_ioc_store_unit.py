from analysis.campaign_detector import Campaign
from api.ioc_store import open_db, query_campaigns, query_commands, replace_campaigns, upsert_session


def test_query_commands_returns_observed_session_commands(tmp_path):
    conn = open_db(str(tmp_path / "iocs.db"))

    upsert_session(conn, "s1", "1.1.1.1", "2026-06-01T10:00:00Z", "2026-06-01T10:01:00Z",
                   ["whoami", "id"], None, None, "2026-06-01T10:01:00Z")
    upsert_session(conn, "s2", "2.2.2.2", "2026-06-01T10:02:00Z", "2026-06-01T10:03:00Z",
                   ["whoami", "uname -a"], None, None, "2026-06-01T10:03:00Z")
    conn.commit()

    result = query_commands(conn)

    assert result["total"] == 4
    assert result["commands"][0] == {"command": "whoami", "count": 2}
    assert {"command": "id", "count": 1} in result["commands"]
    assert {"command": "uname -a", "count": 1} in result["commands"]


def test_query_campaigns_includes_observed_commands_even_when_not_shared(tmp_path):
    conn = open_db(str(tmp_path / "iocs.db"))
    now = "2026-06-01T10:05:00Z"

    upsert_session(conn, "s1", "1.1.1.1", "2026-06-01T10:00:00Z", "2026-06-01T10:01:00Z",
                   ["whoami", "id"], None, None, now)
    upsert_session(conn, "s2", "2.2.2.2", "2026-06-01T10:02:00Z", "2026-06-01T10:03:00Z",
                   ["uname -a"], None, None, now)
    replace_campaigns(conn, [
        Campaign(
            campaign_id="C001",
            ips=["1.1.1.1", "2.2.2.2"],
            subnet=None,
            asn=None,
            time_start="2026-06-01T10:00:00Z",
            time_end="2026-06-01T10:03:00Z",
            session_count=2,
            shared_commands=[],
            verdict="coincidence",
            confidence=0.30,
        )
    ], now)
    conn.commit()

    campaign = query_campaigns(conn)[0]

    assert campaign["shared_commands"] == []
    assert campaign["command_count"] == 3
    assert {"command": "whoami", "count": 1} in campaign["observed_commands"]
    assert {"command": "id", "count": 1} in campaign["observed_commands"]
    assert {"command": "uname -a", "count": 1} in campaign["observed_commands"]
