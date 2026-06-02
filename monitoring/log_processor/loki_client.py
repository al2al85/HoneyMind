"""Push log streams to Loki via the HTTP push API."""
import json
import logging
import threading
import time
from collections import defaultdict
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

_BATCH_SIZE = 100
_FLUSH_INTERVAL_S = 2.0


class LokiClient:
    def __init__(self, url: str = "http://loki:3100"):
        self.push_url = f"{url.rstrip('/')}/loki/api/v1/push"
        self._buffer: list[tuple[dict, str, str]] = []  # (labels, ts_ns, line)
        self._lock = threading.Lock()
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._flush_thread.start()

    def push(self, labels: dict[str, str], line: str, timestamp_ns: Optional[str] = None) -> None:
        ts = timestamp_ns or str(int(time.time() * 1e9))
        with self._lock:
            self._buffer.append((labels, ts, line))
            if len(self._buffer) >= _BATCH_SIZE:
                self._drain()

    def _drain(self) -> None:
        if not self._buffer:
            return
        batch = self._buffer[:]
        self._buffer.clear()

        streams: dict[str, list] = defaultdict(list)
        for labels, ts, line in batch:
            key = json.dumps(labels, sort_keys=True)
            streams[key].append([ts, line])

        payload = {
            "streams": [
                {"stream": json.loads(key), "values": values}
                for key, values in streams.items()
            ]
        }

        try:
            r = requests.post(
                self.push_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=5,
            )
            if not r.ok:
                logger.warning(f"Loki push failed: {r.status_code} {r.text[:200]}")
        except Exception as e:
            logger.warning(f"Loki push error: {e}")

    def _flush_loop(self) -> None:
        while True:
            time.sleep(_FLUSH_INTERVAL_S)
            with self._lock:
                self._drain()

    def flush(self) -> None:
        with self._lock:
            self._drain()
