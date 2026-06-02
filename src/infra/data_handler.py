import json
import logging
import os

from pathlib import Path
from typing import List, Optional

from core.honeypot_utils import normalize_backend_name
from core.input_normalizer import input_normalization_enabled, normalize_lookup_key
from infra.data_store import SqliteDataStore, DataStore
from infra.interfaces import HoneypotAction, HoneypotSession
from llm_providers.llm_utils import invoke_llm, InvokeLimiter


class DataHandler(HoneypotAction):
    def __init__(
        self,
        data_file: str,
        system_prompt: str,
        model_id: str,
        structure: dict = None,
        routes: list[dict] = None,
        llm_provider: str = None,
        llm_base_url: str = None,
        llm_api_key: str = None,
        llm_api_key_env: str = None,
        llm_allow_no_api_key: bool = None,
        llm_timeout: int = None,
        llm_temperature: float = None,
        llm_max_tokens: int = None,
        llm_usage_db_path: str = None,
        llm_model_prices: list[dict] = None,
        input_normalization_enabled: bool = None,
        log_normalized_input: bool = None,
    ):
        data_folder = str(Path(data_file).parent.absolute())
        self._data_store = self._create_data_store(data_folder, structure)
        if os.path.exists(data_file):
            self._data_store.load_static_content(data_file)
        self._hints_file = Path(data_file.replace("data", "hints"))
        if isinstance(system_prompt, list):
            system_prompt = "\n".join(system_prompt)
        self._system_prompt = system_prompt
        self._model_id = model_id
        llm_config = {
            "llm_provider": llm_provider,
            "llm_base_url": llm_base_url,
            "llm_api_key": llm_api_key,
            "llm_api_key_env": llm_api_key_env,
            "llm_allow_no_api_key": llm_allow_no_api_key,
            "llm_timeout": llm_timeout,
            "llm_temperature": llm_temperature,
            "llm_max_tokens": llm_max_tokens,
            "llm_usage_db_path": llm_usage_db_path,
            "llm_model_prices": llm_model_prices,
        }
        if llm_usage_db_path is None:
            llm_config["llm_usage_db_path"] = os.path.join(data_folder, "llm_usage.db")
        self._llm_config = {
            key: value for key, value in llm_config.items() if value is not None
        }
        self._data_file = data_file
        self.entries = self._load_data_entries(data_file)
        self._hints = self._load_hints()
        self._limiter = InvokeLimiter(20, 600)
        self._routes = routes or []
        self._input_normalization_enabled = input_normalization_enabled is not False
        self._log_normalized_input = log_normalized_input is not False

    def _load_data_entries(self, path):
        entries = []
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    if line.strip():
                        entries.append(json.loads(line))
        return entries

    @staticmethod
    def _create_data_store(data_folder: str, structure: dict) -> DataStore:
        return SqliteDataStore(
            os.path.join(data_folder, "data_store.db"),
            structure if structure else {"command": "TEXT"},
        )

    def _load_hints(self) -> List[dict]:
        if not self._hints_file.exists():
            return []
        with self._hints_file.open("r") as f:
            return [json.loads(line) for line in f if line.strip()]

    def connect(self, auth_info: dict) -> HoneypotSession:
        # Log the connection (could be extended)
        logging.info(f"DataHandler.connect: {auth_info}")
        session = HoneypotSession()
        for key in auth_info:
            session[key] = auth_info[key]
        return session

    def invoke_llm_with_limit(self, user_prompt: str) -> (bool, str):
        if self._limiter.can_invoke("visitor"):
            response = invoke_llm(
                self._system_prompt,
                user_prompt,
                self._model_id,
                **self._llm_config,
            )
            return True, response
        else:
            return False, "Internal error. Please try again later."

    def query(self, query: str, session: HoneypotSession, **kwargs) -> dict:
        return self.request({"command": query}, session, **kwargs)

    def request_user_prompt(self, info: dict) -> str:
        return f"User input: {info}"

    def _normalize_search_terms(self, info: dict) -> dict:
        if not input_normalization_enabled(
            {"input_normalization_enabled": self._input_normalization_enabled}
        ):
            return dict(info)

        normalized = dict(info)
        for key, value in info.items():
            if not isinstance(value, str):
                continue
            request_type = self._request_type_for_key(key)
            if request_type:
                normalized[key] = normalize_lookup_key(value, request_type)
        return normalized

    @staticmethod
    def _request_type_for_key(key: str) -> Optional[str]:
        if key == "command":
            return "command"
        if key == "query":
            return "sql"
        if key in {"path", "args", "routing_key"}:
            return "http"
        return None

    def _search_with_raw_fallback(self, raw_info: dict) -> tuple[Optional[str], dict]:
        lookup_info = self._normalize_search_terms(raw_info)
        result = self._data_store.search(lookup_info)
        if result:
            return result, lookup_info

        if lookup_info != raw_info:
            result = self._data_store.search(raw_info)
            if result:
                logging.info(
                    f"DataHandler.request: Found cached response for raw fallback {raw_info}"
                )
                self._data_store.store(lookup_info, result)
                return result, raw_info

        return None, lookup_info

    def user_prompt_hint(self, info: dict) -> Optional[str]:
        for entry in self._hints:
            if entry["path"] == info["path"] and entry["args"] == info["args"]:
                return entry["content"]
        return None

    def request(self, info: dict, session: HoneypotSession, **kwargs) -> dict:
        result, lookup_info = self._search_with_raw_fallback(info)
        if result:
            logging.info(f"DataHandler.request: Found cached response for {lookup_info}")
            session["_last_parser_action"] = "hardcoded"
            return {"output": result}

        invoked, response = self.invoke_llm_with_limit(self.request_user_prompt(info))
        if invoked:
            self._data_store.store(lookup_info, response)
            session["_last_parser_action"] = "llm"
        else:
            session["_last_parser_action"] = "blocked"
        return {"output": response}

    def dispatch(
        self, query_input: dict, session: HoneypotSession
    ) -> str | dict | None:
        """
        Decide which backend to use for dispatcher mode.
        Returns:
          - backend name (normalized) present in query_input["honeypots"], or
          - dict override {"status","headers","body"} to short-circuit, or
          - None (caller will apply defaults)
        """
        # Normalize key
        key = (query_input.get("routing_key") or "/").lower().rstrip("/") or "/"
        routes = sorted(
            self._routes,
            key=lambda r: len((r.get("path") or "").rstrip("/").lower()),
            reverse=True,
        )

        # Try route matches
        for r in routes:
            p = (r.get("path") or "").lower().rstrip("/") or "/"
            is_root = p == "/" and key == "/"
            is_bound = p != "/" and (key == p or key.startswith(p + "/"))
            if is_root or is_bound:
                name = normalize_backend_name(r.get("name") or "")
                # Allow "UNKNOWN" to fall back to first available
                if name == "unknown":
                    break
                return name if name else None

        # Default to first available backend if provided
        hps = query_input.get("honeypots") or []
        if hps:
            # query_input["honeypots"] are already normalized by the caller (dispatcher wiring)
            return hps[0]
        return None
