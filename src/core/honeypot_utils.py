import logging
import os
import socket
from pathlib import Path
from time import sleep

_PROJECT_FOLDER = Path(os.path.dirname(os.path.abspath(__file__))).parent.absolute()


def get_project_folder() -> str:
    return str(_PROJECT_FOLDER)


def init_env_from_file():
    config_folder = os.path.join(get_project_folder(), "config")
    for file_name in ("aws.env.list", "llm.env.list", ".env"):
        full_file_name = os.path.join(config_folder, file_name)
        if os.path.exists(full_file_name):
            logging.info(f"Going to set env variables from file: {full_file_name}")
            _load_env_file(full_file_name)


def _load_env_file(full_file_name: str):
    with open(full_file_name) as f:
        for line_number, line in enumerate(f, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                logging.warning(
                    f"Ignoring malformed env line {line_number} in {full_file_name}"
                )
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key:
                logging.warning(
                    f"Ignoring env line {line_number} with empty key in {full_file_name}"
                )
                continue
            os.environ[key] = value


def allocate_port():
    """
    allocate a dynamic port
    :return: port number
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


def wait_for_port(port: int):
    retries = 3
    for i in range(1, retries + 1):
        try:
            with socket.create_connection(("0.0.0.0", port), timeout=1):
                break
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            if i < retries:
                sleep(0.5 * i)
            else:
                raise e


def normalize_backend_name(raw) -> str:
    """
    Extract and normalize a backend name for robust matching.
    - Accepts str, dict, or any object (coerced to str).
    - For dicts, tries common keys: name, target, backend.
    - Normalizes: lowercase, spaces/dashes -> underscores, strip.
    """
    cand = None
    if isinstance(raw, dict):
        cand = raw.get("name") or raw.get("target") or raw.get("backend")
    else:
        cand = raw
    s = (str(cand or "")).strip()
    s = s.lower().replace(" ", "_").replace("-", "_")
    return s
