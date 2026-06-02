from datetime import datetime, timedelta, timezone

from analysis.campaign_detector import Campaign
from api.ioc_store import (
    open_db,
    query_activity,
    query_campaigns,
    query_commands,
    replace_campaigns,
    upsert_session,
)


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


def test_query_campaigns_reports_per_ip_session_counts_and_closed_status(tmp_path):
    conn = open_db(str(tmp_path / "iocs.db"))
    now = "2026-06-01T10:05:00Z"

    upsert_session(conn, "s1", "1.1.1.1", "2026-06-01T10:00:00Z", "2026-06-01T10:01:00Z",
                   ["whoami"], None, None, now)
    upsert_session(conn, "s2", "1.1.1.1", "2026-06-01T10:02:00Z", "2026-06-01T10:03:00Z",
                   ["id"], None, None, now)
    upsert_session(conn, "s3", "2.2.2.2", "2026-06-01T10:04:00Z", "2026-06-01T10:05:00Z",
                   ["uname -a"], None, None, now)
    replace_campaigns(conn, [
        Campaign(
            campaign_id="C001",
            ips=["1.1.1.1", "2.2.2.2"],
            subnet=None,
            asn=None,
            time_start="2026-06-01T10:00:00Z",
            time_end="2026-06-01T10:05:00Z",
            session_count=3,
            shared_commands=[],
            verdict="coincidence",
            confidence=0.30,
        )
    ], now)
    conn.commit()

    campaign = query_campaigns(conn)[0]

    assert campaign["status"] == "closed"
    assert campaign["session_count"] == 3
    assert campaign["ip_session_counts"] == {"1.1.1.1": 2, "2.2.2.2": 1}


def test_query_activity_returns_local_30_day_session_counts(tmp_path):
    conn = open_db(str(tmp_path / "iocs.db"))
    today = datetime.now(timezone.utc).date()
    yesterday = today - timedelta(days=1)
    old = today - timedelta(days=45)

    upsert_session(conn, "s1", "1.1.1.1", f"{today.isoformat()}T10:00:00Z", f"{today.isoformat()}T10:01:00Z",
                   ["whoami"], None, None, f"{today.isoformat()}T10:01:00Z")
    upsert_session(conn, "s2", "2.2.2.2", f"{yesterday.isoformat()}T10:00:00Z", f"{yesterday.isoformat()}T10:01:00Z",
                   ["id"], None, None, f"{yesterday.isoformat()}T10:01:00Z")
    upsert_session(conn, "s3", "3.3.3.3", f"{old.isoformat()}T10:00:00Z", f"{old.isoformat()}T10:01:00Z",
                   ["uname -a"], None, None, f"{old.isoformat()}T10:01:00Z")
    conn.commit()

    activity = query_activity(conn, days=30)
    by_date = {row["date"]: row["attacks"] for row in activity["activity"]}

    assert activity["total"] == 2
    assert by_date[today.isoformat()] == 1
    assert by_date[yesterday.isoformat()] == 1
    assert old.isoformat() not in by_date
