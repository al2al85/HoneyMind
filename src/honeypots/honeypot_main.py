import logging
import os
import sys
from logging.config import fileConfig

from honeypots.honeypot_main_utils import start_dd_honeypot
from core.honeypot_utils import init_env_from_file

_module_dir = os.path.dirname(os.path.abspath(__file__))
_logging_conf = os.path.join(_module_dir, "logging.conf")
if not os.path.exists(_logging_conf):
    _logging_conf = os.path.join(os.path.dirname(_module_dir), "logging.conf")

fileConfig(_logging_conf)
logging.info("Configured logging")

if __name__ == "__main__":
    init_env_from_file()
    honeypot_folder = sys.argv[1] if len(sys.argv) > 1 else "/data/honeypot"
    start_dd_honeypot(honeypot_folder)
