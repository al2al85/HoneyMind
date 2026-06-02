import logging
import random
import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from logging_pipeline.canonical_log_utils import (
    build_command_payload,
    build_event,
    client_identity,
    write_and_print_event,
)
from core.honeypot_utils import allocate_port

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from infra.interfaces import HoneypotAction


class HoneypotSession(dict):
    """
    Honeypot session info, which holds the session id and other information based on past session operations.
    For example, it can hold the user info, the current directory, and other state-related information.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "session_id" not in self:
            self["session_id"] = str(uuid.uuid4())
        if "_seq" not in self:
            self["_seq"] = 0
        if "_last_event_ts" not in self:
            self["_last_event_ts"] = None
        if "_session_start_ts" not in self:
            self["_session_start_ts"] = datetime.now().timestamp() * 1000

    @property
    def session_id(self):
        return self["session_id"]

    def next_seq(self) -> int:
        self["_seq"] += 1
        return self["_seq"]

    def elapsed_ms(self) -> Optional[int]:
        now = datetime.now().timestamp() * 1000
        last = self["_last_event_ts"]
        self["_last_event_ts"] = now
        return int(now - last) if last is not None else None

    def duration_ms(self) -> int:
        now = datetime.now().timestamp() * 1000
        return int(now - self.get("_session_start_ts", now))


class BaseHoneypot(ABC):
    def __init__(
        self,
        port: int = None,
        config: dict = None,
    ):
        super().__init__()
        self._action = None
        self.__port = port if port else allocate_port()
        self.__config = config or {}
        self.is_dispatcher = bool(self.config.get("is_dispatcher"))
        self._session_map: dict[str, str] = {}

    @property
    def action(self) -> "HoneypotAction":
        return self._action

    @action.setter
    def action(self, value: "HoneypotAction"):
        self._action = value

    @property
    def port(self):
        """
        :return: port number
        """
        return self.__port

    @port.setter
    def port(self, value: int):
        """
        Set the port_number
        :param value: port number
        """
        self.__port = value

    @property
    def name(self) -> Optional[str]:
        """
        :return: name of the honeypot
        """
        return self.__config.get("name") if self.__config else None

    @property
    def config(self) -> Optional[dict]:
        """
        :return: name of the honeypot
        """
        return self.__config

    @abstractmethod
    def start(self):
        """
        Start the honeypot, after this method is called, the honeypot should be running and listening on the given port
        """
        raise NotImplementedError()

    @abstractmethod
    def stop(self):
        """
        Stop the honeypot and release all resources
        """
        raise NotImplementedError()

    # noinspection PyMethodMayBeStatic
    def is_running(self) -> bool:
        """

        :return: True if the honeypot is running, False otherwise
        """
        return True

    def honeypot_type(self) -> str:
        """
        :return: the type of the honeypot, for example, "HTTP", "SSH", etc.
        """
        return self.__class__.__name__

    def log_login(self, session: HoneypotSession, data: dict):
        """
        log login data for the honeypot session. This can be used to log user login attempts, successful logins,
        :param session:
        :param data:
        """
        attempt = session.get("_last_auth_attempt") or {}
        self.log_auth_attempt(
            session,
            username=attempt.get("username", data.get("username")),
            password=attempt.get("password", data.get("password")),
            client_ip=attempt.get("client_ip", data.get("client_ip")),
            attempt_number=attempt.get("attempt_number", data.get("attempt_number")),
            required_attempts=attempt.get(
                "required_attempts", data.get("required_attempts")
            ),
            success=bool(attempt.get("success", data.get("success"))),
        )

    def _protocol(self) -> str:
        return self.__class__.__name__.replace("Honeypot", "").lower()

    @staticmethod
    def _extract_client_ip(data: dict) -> Optional[str]:
        if data.get("client_ip"):
            return data["client_ip"]
        login = data.get("login") or {}
        if isinstance(login, dict) and login.get("client_ip"):
            return login["client_ip"]
        http = data.get("http-request") or {}
        if isinstance(http, dict) and http.get("client_ip"):
            return http["client_ip"]
        return None

    def log_data(self, session: HoneypotSession, data: dict):
        """
        log data for the honeypot session. This can be used to log user commands, requests, and other data.
        :param session:
        :param data:
        """
        if "command" in data:
            self.log_command(
                session,
                raw=data.get("command", ""),
                response=data.get("response", ""),
                parser_action=data.get("parser_action", "unknown"),
                exit_code=data.get("exit_code", 0),
                client_ip=data.get("client_ip"),
                username=data.get("username"),
            )
            return

        details = dict(data)
        client_ip = self._extract_client_ip(details)
        event = build_event(
            session=session,
            event_type=details.pop("event_type", "error"),
            service=self._protocol(),
            config=self.config,
            port=self.port,
            client=client_identity(
                ip=client_ip,
                username=details.pop("username", session.get("username")),
                session=session,
            ),
            details=details,
        )
        write_and_print_event(event, self.config)

    def log_session_start(
        self,
        session: HoneypotSession,
        *,
        client_ip: Optional[str] = None,
        username: Optional[str] = None,
    ) -> dict:
        event = build_event(
            session=session,
            event_type="session_start",
            service=self._protocol(),
            config=self.config,
            port=self.port,
            client=client_identity(ip=client_ip, username=username, session=session),
        )
        write_and_print_event(event, self.config)
        return event

    def log_session_end(
        self,
        session: HoneypotSession,
        *,
        client_ip: Optional[str] = None,
        username: Optional[str] = None,
        close_reason: Optional[str] = None,
    ) -> dict:
        details = {
            "duration_ms": session.duration_ms()
            if hasattr(session, "duration_ms")
            else None,
            "auth_attempts": session.get("_auth_attempts", 0),
            "commands": session.get("_commands", 0),
            "authenticated": bool(session.get("_auth_success")),
            "close_reason": close_reason,
        }
        event = build_event(
            session=session,
            event_type="session_end",
            service=self._protocol(),
            config=self.config,
            port=self.port,
            client=client_identity(ip=client_ip, username=username, session=session),
            details=details,
        )
        write_and_print_event(event, self.config)
        return event

    def log_auth_attempt(
        self,
        session: HoneypotSession,
        *,
        username: str,
        password: str,
        client_ip: Optional[str],
        attempt_number: Optional[int],
        required_attempts: Optional[int],
        success: bool,
    ) -> dict:
        session["username"] = username
        session["client_ip"] = client_ip
        session["_auth_attempts"] = int(session.get("_auth_attempts", 0)) + 1
        session["_auth_success"] = bool(session.get("_auth_success")) or success
        event = build_event(
            session=session,
            event_type="auth_attempt",
            service=self._protocol(),
            config=self.config,
            port=self.port,
            client=client_identity(ip=client_ip, username=username, session=session),
            auth={
                "method": "password",
                "password": password,
                "attempt_number": attempt_number,
                "required_attempts": required_attempts,
                "success": success,
            },
        )
        write_and_print_event(event, self.config)
        return event

    def log_command(
        self,
        session: HoneypotSession,
        *,
        raw: str,
        response: str,
        parser_action: str = "unknown",
        exit_code: Optional[int] = 0,
        client_ip: Optional[str] = None,
        username: Optional[str] = None,
    ) -> dict:
        session["_commands"] = int(session.get("_commands", 0)) + 1
        event = build_event(
            session=session,
            event_type="command",
            service=self._protocol(),
            config=self.config,
            port=self.port,
            client=client_identity(ip=client_ip, username=username, session=session),
            command=build_command_payload(
                raw,
                parser_action=parser_action,
                exit_code=exit_code,
                response=response,
            ),
        )
        write_and_print_event(event, self.config)
        return event

    def forward_to_backend(self, backend_name: str, ctx: dict):
        try:
            handler = BaseHoneypot.get_honeypot_by_name(backend_name)
            return handler.handle_request(ctx)
        except KeyError:
            from honeypots.honeypot_registry import get_honeypot_registry

            registry = get_honeypot_registry()
            names = registry.get_honeypot_names()
            if names:
                name = random.choice(names)
                handler = BaseHoneypot.get_honeypot_by_name(name)
                return handler.handle_request(ctx)
            return 502, {"Content-Type": "text/plain"}, b"Bad Gateway"

    def dispatch(self, ctx: dict) -> tuple[int, dict, str | bytes]:
        session_id = ctx.get("session_id") or str(uuid.uuid4())
        routing_key = (ctx.get("routing_key") or "/").lower()
        meta = ctx.get("meta") or {}

        if self.action and hasattr(self.action, "dispatch"):
            try:
                choice = self.action.dispatch(
                    {
                        "routing_key": routing_key,
                        "meta": meta,
                        "honeypots": self.config.get("honeypots", []),
                    },
                    HoneypotSession(session_id=session_id),
                )
                if isinstance(choice, dict) and {"status", "headers", "body"} <= set(
                    choice
                ):
                    return (
                        choice["status"],
                        choice.get("headers", {}),
                        choice.get("body", ""),
                    )
                if isinstance(choice, str):
                    self._session_map[session_id] = choice
                    return self.forward_to_backend(choice, ctx)
            except Exception as e:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Exception in action.dispatch: {e}")

        pinned = self._session_map.get(session_id)
        if pinned:
            return self.forward_to_backend(pinned, ctx)

        from honeypots.honeypot_registry import get_honeypot_registry

        registry = get_honeypot_registry()
        names = registry.get_honeypot_names()
        if names:
            name = random.choice(names)
            self._session_map[session_id] = name
            return self.forward_to_backend(name, ctx)

        return 502, {"Content-Type": "text/plain"}, b"Bad Gateway"

    @staticmethod
    def get_honeypot_by_name(name: str):
        from honeypots.honeypot_registry import get_honeypot_registry

        return get_honeypot_registry().get_honeypot(name)

    def handle_request(self, ctx: dict) -> tuple:
        raise NotImplementedError("handle_request must be implemented by subclasses")
