import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

DEFAULT_LOCAL_LOG_DIR = "/data/honeypot/logs"
DEFAULT_LOCAL_LOG_FILENAME = "dd-honeypot-%Y-%m-%d.jsonl"

logger = logging.getLogger(__name__)
_WARNED_LOCAL_LOG_FAILURES: set[str] = set()


def local_logging_enabled(config: Optional[dict]) -> bool:
    if config and "local_logging_enabled" in config:
        return bool(config.get("local_logging_enabled"))
    return True


def local_log_path(config: Optional[dict], now: Optional[datetime] = None) -> Path:
    now = now or datetime.now()
    config = config or {}
    log_dir = config.get("local_log_dir") or DEFAULT_LOCAL_LOG_DIR
    filename = config.get("local_log_filename") or DEFAULT_LOCAL_LOG_FILENAME
    rotate_daily = config.get("local_log_rotate_daily", True)
    if rotate_daily:
        filename = now.strftime(filename)
    return Path(log_dir) / filename


def event_to_json(event: dict[str, Any]) -> str:
    return json.dumps(event, default=str, ensure_ascii=False)


def write_local_event(event: dict[str, Any], config: Optional[dict]) -> None:
    if not local_logging_enabled(config):
        return

    try:
        path = local_log_path(config)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(event_to_json(event))
            f.write("\n")
            f.flush()
    except Exception as ex:
        key = f"{type(ex).__name__}:{ex}"
        if key not in _WARNED_LOCAL_LOG_FAILURES:
            _WARNED_LOCAL_LOG_FAILURES.add(key)
            logger.warning(f"Local honeypot logging failed: {ex}")
