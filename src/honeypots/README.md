# Honeypot Package Status

This package contains the protocol runtime code inherited from ThalesGroup dd-honeypot and the maintained HoneyMind SSH runtime.

## Supported HoneyMind Runtime

| File | Status | Notes |
| ---- | ------ | ----- |
| `ssh_honeypot.py` | Supported | Current maintained HoneyMind honeypot protocol. |
| `base_honeypot.py` | Shared | Base abstractions used by supported and legacy handlers. |
| `honeypot_main.py` | Shared | Container entrypoint for loading honeypot configs. |
| `honeypot_main_utils.py` | Shared | Startup helpers and config folder scanning. |
| `honeypot_registry.py` | Shared | Registry used by startup and legacy dispatcher paths. |

## Legacy/Experimental Handlers

These files are kept for reference and future development, but they are not the supported HoneyMind deployment path today:

| File | Origin |
| ---- | ------ |
| `http_honeypot.py` | Inherited HTTP handler. |
| `http_data_handlers.py` | Inherited HTTP data handler. |
| `mysql_honeypot.py` | Inherited MySQL handler. |
| `postgresql_honeypot.py` | Inherited PostgreSQL handler. |
| `redis_honeypot.py` | Inherited Redis handler. |
| `tcp_honeypot.py` | Inherited generic TCP handler. |
| `telnet_honeypot.py` | Inherited Telnet handler. |
| `sql_data_handler.py` | Inherited SQL helper for database experiments. |

Before promoting any legacy handler, revalidate:

- protocol behavior,
- canonical HoneyMind logging,
- local dashboard/IOC pipeline compatibility,
- tests and CI coverage,
- public documentation and examples.
