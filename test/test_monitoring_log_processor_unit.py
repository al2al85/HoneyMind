import importlib
import sys
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PROCESSOR_DIR = ROOT / "monitoring" / "log_processor"


def _processor_module():
    class FakeMetric:
        def __init__(self, *args, **kwargs):
            pass

        def labels(self, **kwargs):
            return self

        def inc(self, *args, **kwargs):
            return None

        def set(self, *args, **kwargs):
            return None

        def observe(self, *args, **kwargs):
            return None

    sys.modules["prometheus_client"] = types.SimpleNamespace(
        Counter=FakeMetric,
        Gauge=FakeMetric,
        Histogram=FakeMetric,
        start_http_server=lambda *args, **kwargs: None,
    )
    sys.modules.pop("main", None)
    sys.modules.pop("metrics", None)
    sys.path.insert(0, str(PROCESSOR_DIR))
    try:
        return importlib.import_module("main")
    finally:
        sys.path.remove(str(PROCESSOR_DIR))


def test_command_events_build_parser_action_label():
    processor = _processor_module()
    event = {
        "schema_version": 1,
        "event_type": "command",
        "service": "ssh",
        "session_id": "s1",
        "client": {"ip": "1.2.3.4"},
        "command": {
            "raw": "whoami",
            "normalized": "whoami",
            "parser_action": "hardcoded",
        },
        "_attack_category": "DISCOVERY",
    }

    labels = processor._build_labels(event)

    assert labels["parser_action"] == "hardcoded"
    processor._record_metrics(event)
