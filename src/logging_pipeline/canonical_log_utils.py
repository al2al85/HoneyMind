import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from core.input_normalizer import normalize_command_input
from logging_pipeline.local_log_utils import write_local_event

SCHEMA_VERSION = 1
DEFAULT_SERVICE = "ssh"
EVENT_TYPES = {
    "auth_attempt",
    "auth_success",
    "auth_failure",
    "command",
    "session_start",
    "session_end",
    "error",
    "llm_response",
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(dt: Optional[datetime] = None) -> str:
    return (dt or utc_now()).isoformat().replace("+00:00", "Z")


def honeypot_identity(config: Optional[dict], port: Optional[int] = None) -> dict[str, Any]:
    config = config or {}
    name = config.get("name") or config.get("honeypot_name")
    profile = config.get("profile") or config.get("type") or config.get("name")
    return {
        "name": name,
        "profile": profile,
        "port": port if port is not None else config.get("port"),
    }


def client_identity(
    *,
    ip: Optional[str] = None,
    username: Optional[str] = None,
    session: Optional[dict] = None,
) -> dict[str, Any]:
    session = session or {}
    return {
        "ip": ip if ip is not None else session.get("client_ip"),
        "username": username if username is not None else session.get("username"),
    }


def next_session_seq(session: dict) -> int:
    if hasattr(session, "next_seq"):
        return session.next_seq()
    session["_seq"] = int(session.get("_seq", 0)) + 1
    return session["_seq"]


def session_timing(session: dict, now: Optional[datetime] = None) -> dict[str, Optional[int]]:
    now = now or utc_now()
    now_ms = now.timestamp() * 1000
    start_ms = session.get("_session_start_ts")
    if start_ms is None:
        start_ms = now_ms
        session["_session_start_ts"] = start_ms

    previous_ms = session.get("_last_event_ts")
    session["_last_event_ts"] = now_ms
    return {
        "since_session_start_ms": int(now_ms - start_ms),
        "since_previous_event_ms": int(now_ms - previous_ms)
        if previous_ms is not None
        else None,
    }


def build_event(
    *,
    session: dict,
    event_type: str,
    service: str = DEFAULT_SERVICE,
    config: Optional[dict] = None,
    port: Optional[int] = None,
    client: Optional[dict[str, Any]] = None,
    auth: Optional[dict[str, Any]] = None,
    command: Optional[dict[str, Any]] = None,
    error: Optional[dict[str, Any]] = None,
    llm: Optional[dict[str, Any]] = None,
    details: Optional[dict[str, Any]] = None,
    timestamp: Optional[datetime] = None,
) -> dict[str, Any]:
    if event_type not in EVENT_TYPES:
        raise ValueError(f"Unknown canonical event_type: {event_type}")
    if "session_id" not in session:
        session["session_id"] = str(uuid.uuid4())

    ts = timestamp or utc_now()
    event = {
        "schema_version": SCHEMA_VERSION,
        "timestamp": iso_utc(ts),
        "event_id": str(uuid.uuid4()),
        "session_id": session["session_id"],
        "seq": next_session_seq(session),
        "event_type": event_type,
        "service": service,
        "honeypot": honeypot_identity(config, port),
        "client": client or client_identity(session=session),
        "timing": session_timing(session, ts),
    }
    if auth is not None:
        event["auth"] = auth
    if command is not None:
        event["command"] = command
    if error is not None:
        event["error"] = error
    if llm is not None:
        event["llm"] = llm
    if details is not None:
        event["details"] = details
    return event


def build_command_payload(
    raw: str,
    *,
    normalized: Optional[str] = None,
    parser_action: str = "unknown",
    exit_code: Optional[int] = 0,
    response: Any = "",
) -> dict[str, Any]:
    return {
        "raw": raw,
        "normalized": normalized if normalized is not None else normalize_command_input(raw),
        "parser_action": parser_action,
        "exit_code": exit_code,
        "response": "" if response is None else str(response),
    }


def write_and_print_event(event: dict[str, Any], config: Optional[dict]) -> None:
    write_local_event(event, config)
    from logging_pipeline.local_log_utils import event_to_json

    print(event_to_json(event))


def convert_legacy_event(event: dict[str, Any]) -> dict[str, Any]:
    """Best-effort conversion for older HoneyMind/dd-honeypot JSONL events."""
    session_id = event.get("session_id") or event.get("session-id") or str(uuid.uuid4())
    session = {
        "session_id": session_id,
        "_seq": int(event.get("seq", 0)) - 1 if event.get("seq") else 0,
    }
    service = event.get("protocol") or event.get("service") or DEFAULT_SERVICE
    client_ip = event.get("client_ip")
    username = event.get("username")
    login = event.get("login") if isinstance(event.get("login"), dict) else {}
    if login:
        client_ip = login.get("client_ip", client_ip)
        username = login.get("username", username)
        return build_event(
            session=session,
            event_type="auth_attempt",
            service=service,
            config={"name": event.get("name")},
            port=event.get("port"),
            client=client_identity(ip=client_ip, username=username),
            auth={
                "method": "password",
                "password": login.get("password"),
                "attempt_number": login.get("attempt_number"),
                "required_attempts": login.get("required_attempts"),
                "success": bool(login.get("success")),
            },
        )

    command_value = event.get("command") or event.get("raw_input")
    if command_value is not None:
        return build_event(
            session=session,
            event_type="command",
            service=service,
            config={"name": event.get("name")},
            port=event.get("port"),
            client=client_identity(ip=client_ip, username=username),
            command=build_command_payload(
                str(command_value),
                normalized=event.get("normalized_command") or event.get("normalized_input"),
                parser_action=event.get("parser_action", "unknown"),
                response=event.get("response", ""),
            ),
        )

    return build_event(
        session=session,
        event_type="error" if event.get("error") else "session_start",
        service=service,
        config={"name": event.get("name")},
        port=event.get("port"),
        client=client_identity(ip=client_ip, username=username),
        details={"legacy_event": event},
    )
