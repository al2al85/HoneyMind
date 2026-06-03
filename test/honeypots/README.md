# Honeypot Test Fixtures

This directory contains test fixtures for the HoneyMind codebase.

Supported HoneyMind runtime fixtures:

- `alpine/`
- `busybox/`
- `mysql_ssh/`

Legacy/experimental fixtures inherited from ThalesGroup dd-honeypot are kept for regression tests and future protocol work:

- `boa_server_http/`
- `dlink_telnet/`
- `http_dispatcher/`
- `mysql/`
- `php_my_admin/`
- `postgres/`
- `redis/`

Do not treat every fixture in this directory as a supported HoneyMind deployment example. The current maintained HoneyMind honeypot protocol is SSH.
