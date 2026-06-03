import json
import logging
import os

from honeypots.base_honeypot import BaseHoneypot
from honeypots.http_data_handlers import HTTPDataHandler
from honeypots.http_honeypot import HTTPHoneypot
from infra.file_download_handler import FileDownloadHandler
from infra.chain_honeypot_action import ChainedHoneypotAction
from infra.chained_data_handler import ChainedDataHandler
from infra.data_handler import DataHandler
from infra.fake_fs_data_handler import FakeFSDataHandler
from honeypots.sql_data_handler import SqlDataHandler
from honeypots.telnet_honeypot import TelnetHoneypot

logger = logging.getLogger(__name__)

LLM_CONFIG_KEYS = (
    "llm_provider",
    "llm_base_url",
    "llm_api_key",
    "llm_api_key_env",
    "llm_allow_no_api_key",
    "llm_timeout",
    "llm_temperature",
    "llm_max_tokens",
    "llm_usage_db_path",
    "llm_model_prices",
    "input_normalization_enabled",
    "log_normalized_input",
)


def llm_config_from(config: dict) -> dict:
    return {key: config[key] for key in LLM_CONFIG_KEYS if key in config}


def build_data_handler(config: dict, log_callback=None):
    data_file = str(config["data_file"])
    model_id = config["model_id"]
    system_prompt = config["system_prompt"]
    fs_file = config.get("fs_file")
    llm_config = llm_config_from(config)

    llm_handler = DataHandler(
        data_file=data_file,
        system_prompt=system_prompt,
        model_id=model_id,
        **llm_config,
    )

    if config.get("type") == "ssh":
        if fs_file:
            fakefs_handler = FakeFSDataHandler(
                data_file=data_file,
                fs_file=fs_file,
                config=config,
            )
            file_download_handler = FileDownloadHandler(
                fakefs_handler=fakefs_handler, log_callback=log_callback
            )
            return ChainedDataHandler(
                [file_download_handler, fakefs_handler, llm_handler]
            )
        else:
            # No fakefs — still intercept wget/curl to save downloads to disk
            file_download_handler = FileDownloadHandler(log_callback=log_callback)
            return ChainedDataHandler([file_download_handler, llm_handler])

    return llm_handler


def create_honeypot(config: dict) -> BaseHoneypot:
    required_keys = ["type", "data_file", "model_id", "system_prompt", "port"]
    for key in required_keys:
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")

    honeypot_type = config["type"]
    port = config["port"]

    if honeypot_type == "http":
        action = HTTPDataHandler(
            data_file=str(config["data_file"]),
            system_prompt=config["system_prompt"],
            model_id=config["model_id"],
            **llm_config_from(config),
        )
        hp = HTTPHoneypot(port=port, action=action, config=config)
        return hp

    action = build_data_handler(config, log_callback=None)

    if honeypot_type == "ssh":
        from honeypots.ssh_honeypot import SSHHoneypot

        hp = SSHHoneypot(port=port, action=action, config=config)
        if isinstance(action, ChainedDataHandler):
            action.log_callback = hp.log_data
        return hp

    elif honeypot_type == "tcp":
        from honeypots.tcp_honeypot import TCPHoneypot

        hp = TCPHoneypot(port=port, action=action, config=config)
        return hp

    elif honeypot_type == "telnet":
        hp = TelnetHoneypot(port=port, action=action, config=config)
        return hp

    elif honeypot_type in ("mysql", "postgres"):

        from honeypots.mysql_honeypot import MySQLHoneypot
        from honeypots.postgresql_honeypot import PostgresHoneypot

        dialect = config.get("dialect", honeypot_type)
        sql_handler = SqlDataHandler(dialect=dialect)
        chained_action = ChainedHoneypotAction(action, sql_handler)
        # Choose appropriate honeypot class
        honeypot_cls = MySQLHoneypot if honeypot_type == "mysql" else PostgresHoneypot
        hp = honeypot_cls(port=port, action=chained_action, config=config)
        return hp
    elif honeypot_type == "redis":
        from honeypots.redis_honeypot import RedisHoneypot

        hp = RedisHoneypot(port=port, action=action, config=config)
        return hp
    else:
        raise ValueError(f"Unsupported honeypot type: {honeypot_type}")


def create_honeypot_by_folder(folder_path: str) -> BaseHoneypot:
    config_path = os.path.join(folder_path, "config.json")
    data_file_path = os.path.join(folder_path, "data.jsonl")

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Missing config.json in {folder_path}")

    with open(config_path) as f:
        config = json.load(f)

    config["config_dir"] = folder_path
    config["data_file"] = data_file_path

    if "fs_file" in config:
        fs_file_candidate = os.path.join(
            folder_path, os.path.basename(config["fs_file"])
        )
        if os.path.exists(fs_file_candidate):
            config["fs_file"] = fs_file_candidate
        else:
            logging.warning(
                f"fs_file declared but not found: {fs_file_candidate}. Continuing without fakefs."
            )
            config.pop("fs_file")

    config["data_file"] = data_file_path

    passwords_file = os.path.join(folder_path, "passwords.txt")
    if os.path.exists(passwords_file) and "passwords_file" not in config:
        config["passwords_file"] = passwords_file

    return create_honeypot(config)
