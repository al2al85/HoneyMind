# Project Structure

HoneyMind organizes implementation code into domain packages under `src/`. The `src/` root intentionally contains no Python modules, so imports point directly at the package that owns the behavior.

## Source Layout

| Path | Purpose |
| ---- | ------- |
| `src/honeypots/` | Honeypot startup helpers and protocol handlers. SSH is supported; non-SSH handlers are legacy/experimental. See `src/honeypots/README.md`. |
| `src/infra/` | Shared data handler chain, fake filesystem, datastore, and prompt rendering infrastructure |
| `src/core/` | Shared runtime utilities such as environment loading, input normalization, and password handling |
| `src/llm_providers/` | LLM provider abstraction and usage accounting |
| `src/logging_pipeline/` | Canonical structured logging and local JSONL log writing |
| `src/analysis/` | Attack classification, profiling, campaign detection, enrichment, and fingerprint helpers |

## Honeypot Package Status

`src/honeypots/` intentionally keeps inherited files visible instead of hiding or deleting them. This helps future protocol work while making the current support boundary explicit.

| File group | Status | Notes |
| ---------- | ------ | ----- |
| `ssh_honeypot.py` | Supported | Current HoneyMind honeypot protocol. |
| `base_honeypot.py`, `honeypot_main.py`, `honeypot_main_utils.py`, `honeypot_registry.py` | Shared | Startup and base runtime used by the supported SSH path and some inherited code. |
| `http_*`, `mysql_honeypot.py`, `postgresql_honeypot.py`, `redis_honeypot.py`, `tcp_honeypot.py`, `telnet_honeypot.py`, `sql_data_handler.py` | Legacy/experimental | Inherited from ThalesGroup dd-honeypot. Revalidate behavior, logs, tests, and docs before promoting. |

## Application and Monitoring Layout

| Path | Purpose |
| ---- | ------- |
| `website/` | HoneyMind web dashboard. This is an internal monitoring and analysis UI, not a honeypot service. |
| `monitoring/` | Optional Grafana, Loki, Prometheus, and log processor stack for local operational monitoring. |
| `honeypots/` | Runtime honeypot configurations mounted into containers. Supported HoneyMind deployments should use SSH configs. See `honeypots/README.md`. |
| `logs/` | Local JSONL logs and derived SQLite databases when mounted from Docker. |

The repository still contains inherited non-SSH protocol code from ThalesGroup dd-honeypot. Those handlers are kept for reference and future development, but SSH is the current supported HoneyMind honeypot protocol.

## Scripts

| Path | Purpose |
| ---- | ------- |
| `scripts/` | Operational utilities for logs, analytics, LLM usage, and filesystem packing |
| `scripts/fakefs/` | Fake filesystem conversion helpers used by the FakeFS guide |

## Tests

Unit tests remain in `test/` because the CI command runs `test/*_unit.py`. New tests should keep that naming convention unless the CI workflow changes.

`test/honeypots/` contains both supported SSH fixtures and legacy protocol fixtures used for regression coverage. See `test/honeypots/README.md` before copying a fixture into a runtime deployment.

## Import Guidance

New code should import from the organized packages, for example:

```python
from honeypots.ssh_honeypot import SSHHoneypot
from core.input_normalizer import normalize_command_input
from llm_providers.llm_utils import invoke_llm
```
