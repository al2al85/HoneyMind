# HoneyMind

![HoneyMind screenshot](docs/assets/honeymind-screenshot.png)

HoneyMind is a local-first, cloud-optional, LLM-powered honeypot and attack analytics platform. It uses dynamic honeypot interactions to collect attacker behavior and make the resulting logs easier to analyze afterward.

The current HoneyMind product focuses on a realistic SSH honeypot, local JSONL logging, Grafana-based operational monitoring, and a dedicated web dashboard for attack analysis. The repository still contains protocol handlers inherited from the original dd-honeypot project, but those non-SSH handlers are not the supported HoneyMind path yet.

When an attacker’s request matches the dataset, the recorded response is returned directly. When no match is found, an LLM generates a realistic response that is logged for review and future inclusion in the dataset. This continuous enrichment process keeps the system effective against emerging threats.

HoneyMind is open-source and welcomes community contributions. Deployment is simplified through a Docker container, enabling users to run the honeypot system fully on one machine with local logs and local LLMs. Cloud LLMs and AWS logging remain optional integrations.

## Origins and attribution

HoneyMind started as a fork/adaptation of ThalesGroup's dd-honeypot. We keep attribution to the original authors and preserve the original license.

Original project: [ThalesGroup/dd-honeypot](https://github.com/ThalesGroup/dd-honeypot)

The current license remains unchanged; see [LICENSE.md](LICENSE.md).

---

## Current Support Status

| Component | Status | Notes |
|-----------|--------|-------|
| SSH honeypot | Supported | Main HoneyMind honeypot surface. Includes shell simulation, fake filesystem, deterministic recon commands, LLM fallback, session tracking, file download handling, and canonical JSON logs. |
| Local JSONL logging | Supported | Default logging path. Logs are readable directly from the host through a mounted folder. |
| Web dashboard | Supported | Internal analysis UI for sessions, IOC, commands, campaigns, activity, map view, reports, and LLM usage. This is not a honeypot service. |
| Grafana monitoring | Supported | Optional local monitoring stack using Loki, Prometheus, Grafana, and the log processor. |
| AWS Bedrock and AWS log export | Optional integration | Kept for users who explicitly configure Bedrock or AWS logging. AWS is not required. |
| HTTP, MySQL, PostgreSQL, Redis, Telnet, generic TCP | Legacy/experimental | Code inherited from ThalesGroup dd-honeypot remains in the repository, but these protocols are not the current supported HoneyMind deployment path and may be incomplete or stale. |

---

## Features

* Realistic SSH honeypot behavior with deterministic Linux reconnaissance responses and LLM fallback for unknown commands
* LLM fallback for unknown requests via local Ollama, OpenAI-compatible APIs, OpenAI, Anthropic, or optional AWS Bedrock, with rate limiting per visitor
* Dataset-first design: JSONL files with dynamic placeholders (`${user}`, `${host}`, etc.)
* Attack analysis dashboard: sessions, campaigns, IOC, commands, activity, source map, LLM cost, and campaign reports
* Grafana monitoring stack for local operational visibility through Loki and Prometheus
* Dispatcher mode from the upstream project remains documented as experimental/legacy ([docs](docs/dispatcher.md))
* Fake filesystem: compressed JSONL definitions loaded into SQLite, enriched with a HoneyMind Linux profile for shell commands and common file reconnaissance
* Chained data handlers: file downloads → fake filesystem → dataset lookup → LLM fallback
* Conservative input normalization for lookup/cache deduplication while preserving raw forensic logs
* Session tracking with UUIDs, client IP logging, and per-session state
* Local JSONL logging with honeypot metadata, plus optional Fluent Bit, CloudWatch, or S3 export
* Docker-based deployment with multi-architecture support (amd64, arm64)

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   SSH Honeypot                      │
│  Shell emulation, auth tracking, session state      │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│                Data Handler Chain                   │
│  Hardcoded commands → File downloads → FakeFS →     │
│  Dataset lookup → Dynamic cache → LLM fallback      │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│             Local JSONL + Usage SQLite              │
│  Canonical events, sessions, commands, LLM costs    │
└──────────────┬──────────────────────────┬───────────┘
               │                          │
┌──────────────▼─────────────┐  ┌────────▼────────────┐
│ IOC writer + IOC API       │  │ Monitoring stack    │
│ Campaigns, IOC, reports    │  │ Loki/Prometheus     │
└──────────────┬─────────────┘  └────────┬────────────┘
               │                         │
        ┌──────▼────────┐         ┌──────▼──────┐
        │ Web dashboard │         │ Grafana     │
        └───────────────┘         └─────────────┘
```

* **SSH Honeypot**: Implements the supported HoneyMind honeypot surface using Paramiko, realistic shell behavior, canonical logging, password attempt tracking, and session state
* **Data Handler Chain**: Processes requests through a configurable pipeline — file downloads, fake filesystem, dataset lookup, and LLM fallback
* **Dataset & Lookup Engine**: Maps incoming requests to recorded payloads in JSONL files backed by SQLite
* **LLM Engine**: Generates realistic responses for unknown requests using local Ollama, OpenAI-compatible APIs, OpenAI, Anthropic, or optional AWS Bedrock with configurable system prompts and per-visitor rate limiting
* **IOC Pipeline**: Reads local logs, extracts IOC, tracks sessions, detects campaigns, and powers the web dashboard
* **Monitoring**: Provides an optional Grafana/Loki/Prometheus stack for local operational visibility
* **Logging**: Tracks all SSH interactions with session IDs, client IPs, timing, commands, parser source, and honeypot metadata in structured JSON format

---

## Dataset

The dataset powers HoneyMind’s response generation. Each JSONL file contains request-response pairs for a specific application and version:

* **request**: the attacker’s input
* **response**: the emulated reply
* Optional placeholders like `${user}` or `${host}` for dynamic substitution
* Context-aware fields (e.g., current working directory, database state)

Datasets can be layered. For SSH, a base Linux command dataset can be combined with a profile-specific fake filesystem and deterministic hardcoded responses for common reconnaissance commands.

**Known requests** are matched and returned directly. **Unknown requests** are handled by the LLM and logged separately for review and future inclusion.

HoneyMind normalizes attacker inputs before dataset and dynamic cache lookup so equivalent whitespace variants reuse the same response. For example, `ls Doc`, `ls                 Doc`, and `ls\tDoc` map to the same lookup key. This reduces duplicate LLM calls, lowers hosted API cost, and keeps responses consistent.

Normalization is intentionally conservative: it strips leading/trailing whitespace and collapses unquoted whitespace, while preserving quoted strings, escaped whitespace, case, paths, argument order, URL encoding, and raw payload content. Raw attacker input remains available in logs and is still used in the LLM prompt on a cache miss.

### Example

```json
{"request": "whoami", "response": "root"}
{"request": "uname -a", "response": "Linux vps-b4c7a33e 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"}
```

For more details on dataset formats, see [data usage](docs/data_usage.md) and [SQLite data handling](docs/sqlite_data_handling.md).

## SSH Fake Filesystem

SSH honeypots can use `fs_file` to load a compressed JSONL fake filesystem into SQLite. HoneyMind now enriches that filesystem with a coherent synthetic Linux server profile by default: Ubuntu-like `/etc` files, `/proc` artifacts, nginx web files under `/var/www/html`, an application under `/srv/app`, logs, cron scripts, backups, and fake sensitive-looking files.

Known fake files and directories are handled locally before the LLM fallback. For example, these commands return deterministic FakeFS responses without sending the interaction to an LLM:

```sh
cat /etc/passwd
cat /srv/app/.env
cat       /srv/app/.env
ls -la /var/www/html
ls -la /srv/app
find / -name "*.env" 2>/dev/null
grep -R "DB_PASSWORD" /srv/app 2>/dev/null
stat /srv/app/.env
file /srv/app/.env
head /srv/app/.env
tail /srv/app/.env
```

The seeded files are synthetic and must stay that way. They may contain plausible placeholders such as `DB_PASSWORD=dev_password_123` or `API_KEY=HONEYMIND_FAKE_API_KEY`, but they must never contain real host data, real private keys, real tokens, or personal information. Unknown paths keep the existing behavior instead of being invented automatically.

To customize the base filesystem, provide your own `.jsonl.gz` via `fs_file`; HoneyMind keeps the existing format and layers the default profile into the same FakeFS store. For generation details, see [FakeFS JSON guide](docs/fakefs_json_guide.md).

---

## Configuration

Each honeypot is defined by a `config.json` in its own directory. The main fields are:

| Field              | Description                                           |
|--------------------|-------------------------------------------------------|
| `type`             | Protocol type. Use `ssh` for the supported HoneyMind honeypot. Other inherited types are experimental/legacy. |
| `port`             | Port to listen on                                     |
| `data_file`        | Path to JSONL dataset (e.g., `data.jsonl`)            |
| `model_id`         | LLM model ID for fallback generation |
| `system_prompt`    | Instructions guiding LLM responses                    |
| `llm_provider`     | Optional LLM provider: `ollama`, `openai_compatible`, `openai`, `anthropic`, or `bedrock` |
| `llm_base_url`     | Optional API base URL for HTTP-based providers        |
| `llm_api_key`      | Optional direct API key or Bearer token value         |
| `llm_api_key_env`  | Optional environment variable containing an API key or Bearer token |
| `llm_allow_no_api_key` | Allow a public OpenAI-compatible endpoint with no API key when explicitly set |
| `llm_temperature`  | Optional generation temperature                       |
| `llm_max_tokens`   | Optional maximum generated tokens                     |
| `llm_timeout`      | Optional LLM request timeout in seconds               |
| `llm_usage_db_path` | Optional SQLite DB path for token usage and pricing  |
| `llm_model_prices` | Optional inline model price table seeded into the usage DB |
| `input_normalization_enabled` | Normalize lookup/cache keys, defaults to `true` |
| `log_normalized_input` | Add normalized input fields to structured logs, defaults to `true` |
| `local_logging_enabled` | Enable local JSONL logs, defaults to `true`      |
| `local_log_dir`    | Directory for JSONL logs, defaults to `/data/honeypot/logs` |
| `name`             | Display name for logging                              |
| `prompt_template`  | Shell prompt format with `${{username}}`, `${{cwd}}` placeholders (SSH) |
| `fs_file`          | Path to compressed fake filesystem (e.g., `fs_alpine.jsonl.gz`) |
| `is_dispatcher`    | Legacy/experimental dispatcher mode inherited from upstream |

### Example: local SSH honeypot with Ollama

```json
{
  "type": "ssh",
  "name": "Alpine Linux",
  "port": 2222,
  "data_file": "data.jsonl",
  "fs_file": "fs_alpine.jsonl.gz",
  "prompt_template": "${username}@alpine:${cwd}$ ",
  "llm_provider": "ollama",
  "llm_base_url": "http://host.docker.internal:11434",
  "model_id": "llama3.1:8b",
  "system_prompt": "You are a terminal on Alpine Linux. Respond only with realistic terminal output.",
  "llm_temperature": 0.0,
  "llm_max_tokens": 2000,
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

For the full configuration schema, see [honeypot configuration](docs/honeypot_configuration.md).

---

## Installation and Usage

HoneyMind is packaged as a Docker image for quick and reproducible deployment.

### 1. Build the Image

```sh
docker build -t honeymind:latest .
```

### 2. Prepare a Local SSH Honeypot

Create a honeypot folder with a `config.json` and a `data.jsonl` file:

```sh
mkdir -p honeypots/ubuntu-ssh logs downloads uploads config
touch honeypots/ubuntu-ssh/data.jsonl
touch config/llm.env.list
```

Example `honeypots/ubuntu-ssh/config.json`:

```json
{
  "type": "ssh",
  "name": "Ubuntu Server",
  "port": 2222,
  "data_file": "data.jsonl",
  "prompt_template": "${username}@vps-b4c7a33e:${cwd}$ ",
  "llm_provider": "ollama",
  "llm_base_url": "http://host.docker.internal:11434",
  "model_id": "llama3.1:8b",
  "system_prompt": "You are an Ubuntu server shell. Respond only with realistic terminal output.",
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

If you use a hosted LLM provider, keep tokens in `config/llm.env.list` and reference them with `llm_api_key_env`. Do not commit this file.

### 3. Run the SSH Honeypot

```sh
docker run --rm -it \
  --name honeymind \
  -p 2222:2222 \
  -v $(pwd)/honeypots:/data/honeypot \
  -v $(pwd)/logs:/data/honeypot/logs \
  -v $(pwd)/downloads:/data/honeypot/downloads \
  -v $(pwd)/uploads:/data/honeypot/uploads \
  --env-file config/llm.env.list \
  honeymind:latest
```

The container starts honeypot services based on the configurations found in `/data/honeypot`. Each subdirectory should contain a `config.json` defining one honeypot instance. Attack logs are written to `/data/honeypot/logs` inside the container, which the example mounts to `./logs` on the host.

### 4. Test the Honeypot

From another terminal:

```sh
ssh -p 2222 root@127.0.0.1
```

HoneyMind intentionally accepts attacker-like credentials according to the configured password policy. Once connected, common reconnaissance commands such as `whoami`, `id`, `uname -a`, `cat /etc/os-release`, `cat /etc/passwd`, `ip a`, `ps aux`, and `cat /proc/cpuinfo` return deterministic Linux-like responses before any LLM fallback is used.

### 5. Read Local Logs

Logs are JSONL files mounted directly on the host:

```sh
tail -f logs/dd-honeypot-$(date +%F).jsonl
python scripts/read_local_logs.py logs
```

### 6. Run the Dashboard and Monitoring Stack

The HoneyMind web dashboard is an internal analysis UI, not a honeypot. It uses local logs plus `ioc-writer` and `ioc-api` to display sessions, IOC, campaigns, commands, activity, source maps, reports, and LLM usage.

Start the local stack:

```sh
docker network create honeymind-monitoring 2>/dev/null || true
docker compose up -d
```

Dashboard:

```text
http://localhost:44806
```

Grafana is optional and runs from the `monitoring/` compose file:

```sh
docker compose -f monitoring/docker-compose.yml up -d
```

Grafana:

```text
http://localhost:3000
```

For details, see [Dashboard and Monitoring](docs/monitoring.md).

### AWS EC2 deployment

1. Create an instance role with permissions for Bedrock, and optionally CloudWatch Logs or S3 if you want AWS log collection
2. Create a security group with the ports your honeypots will use
3. Launch an EC2 instance with the role and security group
4. Install Docker and run:

```sh
docker run -d \
  --log-driver=awslogs \
  --log-opt awslogs-region=us-east-1 \
  --log-opt awslogs-group=yourLogGroup \
  --log-opt awslogs-create-group=true \
  -v /your/honeypot/folder:/data/honeypot \
  honeymind:latest
```

### LLM configuration

HoneyMind uses a dataset-first flow, then falls back to an LLM for unknown requests. AWS is optional. HoneyMind can run locally with local JSONL logs and a local or remote LLM endpoint. If `llm_provider` is omitted, Bedrock model IDs still use Bedrock for backward compatibility; otherwise configure a local or hosted provider explicitly.

Every LLM call can also be recorded in a SQLite usage database. The app stores prompt tokens, completion tokens, total tokens, and an estimated cost when a matching model price row exists. By default the DB is created next to the honeypot data folder as `llm_usage.db`.

Supported providers:

| Provider | Use case |
|----------|----------|
| `ollama` | Native local Ollama `/api/chat` |
| `openai_compatible` | OpenRouter, Groq, Together, Mistral-compatible gateways, vLLM, LM Studio, Ollama `/v1`, and other compatible endpoints |
| `openai` | OpenAI Chat Completions API |
| `anthropic` | Direct Anthropic Messages API |
| `bedrock` | Optional AWS Bedrock Claude and Jamba models |

`llm_api_key_env` takes priority over `llm_api_key` when the environment variable exists and is not empty. Localhost, `127.0.0.1`, `::1`, `host.docker.internal`, and private LAN OpenAI-compatible endpoints can run without a token by default. Public remote OpenAI-compatible endpoints require a token unless `llm_allow_no_api_key` is explicitly set to `true`.

If you want cost tracking, provide `llm_model_prices` inline or seed the `llm_model_prices` table in `llm_usage.db`. Each row uses prices per million tokens (`prompt_price_per_mtok` and `completion_price_per_mtok`) plus a `currency`. Usage rows store generic `prompt_cost`, `completion_cost`, `total_cost`, `currency`, and `price_source` fields. If a model has no matching price row, usage is still logged but the cost columns stay `NULL`. OpenAI-compatible usage can match an `ovhcloud` price row through the built-in provider alias.

You can inspect usage with:

```sh
python scripts/llm_usage_report.py /data/honeypot/logs/llm_usage.db
python scripts/llm_usage_report.py /data/honeypot/logs/llm_usage.db --daily
python scripts/llm_usage_report.py /data/honeypot/logs/llm_usage.db --json
```

Native local Ollama:

```json
{
  "type": "ssh",
  "name": "Alpine Linux",
  "port": 2222,
  "data_file": "data.jsonl",
  "fs_file": "fs_alpine.jsonl.gz",
  "prompt_template": "${username}@alpine:${cwd}$ ",
  "llm_provider": "ollama",
  "llm_base_url": "http://host.docker.internal:11434",
  "model_id": "llama3.1:8b",
  "system_prompt": "You are a terminal on Alpine Linux. Respond only with realistic terminal output.",
  "llm_temperature": 0.0,
  "llm_max_tokens": 2000,
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

Ollama through OpenAI compatibility:

```json
{
  "type": "ssh",
  "name": "Ubuntu Server",
  "port": 2222,
  "data_file": "data.jsonl",
  "llm_provider": "openai_compatible",
  "llm_base_url": "http://host.docker.internal:11434/v1",
  "model_id": "llama3.1:8b",
  "system_prompt": "You are an Ubuntu server shell. Respond only with command output.",
  "llm_temperature": 0.0,
  "llm_max_tokens": 2000,
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

OpenAI API:

```json
{
  "type": "ssh",
  "name": "Ubuntu Server",
  "port": 2222,
  "data_file": "data.jsonl",
  "llm_provider": "openai",
  "llm_api_key_env": "OPENAI_API_KEY",
  "model_id": "gpt-4o-mini",
  "system_prompt": "You are an Ubuntu server shell. Respond only with realistic terminal output.",
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

Anthropic Claude API:

```json
{
  "type": "ssh",
  "name": "Debian Server",
  "port": 2222,
  "data_file": "data.jsonl",
  "llm_provider": "anthropic",
  "llm_api_key_env": "ANTHROPIC_API_KEY",
  "model_id": "claude-3-5-haiku-latest",
  "system_prompt": "You are a Debian terminal. Respond only with realistic terminal output.",
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

Remote vLLM or self-hosted OpenAI-compatible API:

```json
{
  "type": "ssh",
  "name": "Ubuntu Server",
  "port": 2222,
  "data_file": "data.jsonl",
  "llm_provider": "openai_compatible",
  "llm_base_url": "https://llm.example.com/v1",
  "llm_api_key_env": "SELF_HOSTED_LLM_API_KEY",
  "model_id": "meta-llama/Llama-3.1-8B-Instruct",
  "system_prompt": "You are an Ubuntu server shell. Respond only with realistic terminal output.",
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

OpenAI-compatible API with a direct Bearer token:

```json
{
  "llm_provider": "openai_compatible",
  "llm_base_url": "https://example-llm-gateway.com/v1",
  "llm_api_key": "YOUR_TOKEN_HERE",
  "model_id": "your-model-name"
}
```

HoneyMind sends this as:

```http
Authorization: Bearer YOUR_TOKEN_HERE
```

OpenAI-compatible API with a token from the environment:

```json
{
  "llm_provider": "openai_compatible",
  "llm_base_url": "https://example-llm-gateway.com/v1",
  "llm_api_key_env": "HONEYMIND_LLM_TOKEN",
  "model_id": "your-model-name"
}
```

`config/llm.env.list`:

```sh
HONEYMIND_LLM_TOKEN=YOUR_TOKEN_HERE
```

If the configured value already starts with `Bearer `, HoneyMind normalizes it and avoids duplicating the prefix.

Optional AWS Bedrock:

```json
{
  "type": "ssh",
  "name": "Amazon Linux",
  "port": 2222,
  "data_file": "data.jsonl",
  "llm_provider": "bedrock",
  "model_id": "anthropic.claude-3-haiku-20240307-v1:0",
  "system_prompt": "You are an Amazon Linux terminal. Respond only with realistic terminal output.",
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

For hosted HTTP providers, put keys in `config/llm.env.list` or `config/.env`:

```sh
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
OPENROUTER_API_KEY=...
HONEYMIND_LLM_TOKEN=...
```

Remote API providers receive honeypot interaction data when LLM fallback is used. Review privacy, legal, and operational requirements before sending attacker traffic to third-party services.

### Input normalization

HoneyMind keeps the dataset-first and LLM fallback flow, but uses a normalized lookup key before it searches the dataset or dynamic cache. The raw command/request is not replaced.

Example:

```text
ls Doc
ls                 Doc
ls\tDoc
```

All three inputs use `ls Doc` for lookup/cache reuse. If lookup misses, HoneyMind sends the original raw attacker input to the LLM and stores the generated response under the normalized key for future equivalent inputs.

SSH structured logs use the canonical HoneyMind event schema. Command events keep raw attacker input under `command.raw`, normalized lookup input under `command.normalized`, the response sent to the attacker under `command.response`, and the source under `command.parser_action`.

```json
{
  "event_type": "command",
  "command": {
    "raw": "ls                 Doc",
    "normalized": "ls Doc",
    "parser_action": "hardcoded",
    "response": "..."
  }
}
```

The normalizer does not lowercase commands, reorder arguments, decode URLs, expand variables, resolve paths, or deeply rewrite SQL/HTTP payloads.

For AWS Bedrock, provide AWS credentials via environment variables or the backward-compatible `config/aws.env.list` file:

```
AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY
AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY
AWS_REGION=us-east-1
```

Logs are always emitted locally by the honeypot process. Sending them to AWS CloudWatch or S3 is optional and can be configured separately with Docker logging or Fluent Bit.

---

## Documentation

| Topic | Link |
|-------|------|
| Honeypot configuration schema | [docs/honeypot_configuration.md](docs/honeypot_configuration.md) |
| Dashboard and monitoring | [docs/monitoring.md](docs/monitoring.md) |
| Dispatcher (legacy/experimental multi-honeypot routing) | [docs/dispatcher.md](docs/dispatcher.md) |
| Project structure | [docs/project_structure.md](docs/project_structure.md) |
| Fake filesystem guide | [docs/fakefs_json_guide.md](docs/fakefs_json_guide.md) |
| Dataset usage | [docs/data_usage.md](docs/data_usage.md) |
| SQLite data handling | [docs/sqlite_data_handling.md](docs/sqlite_data_handling.md) |
| Redis honeypot legacy notes | [docs/redis_honeypot.md](docs/redis_honeypot.md) |
| Logging and optional Fluent Bit | [docs/logging-readme.md](docs/logging-readme.md) |
| Multi-IP networking | [docs/networking-readme.md](docs/networking-readme.md) |

---

## Contributing

We welcome community contributions — new honeypot types, protocol handlers, datasets, system prompts, and test cases.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup instructions, testing guidelines, and the PR checklist.

---

## Licensing

HoneyMind is distributed under the [Apache 2.0 License](LICENSE.md), preserving the license from the original ThalesGroup dd-honeypot project.
It depends on modules licensed under their own open-source licenses (see [THIRD_PARTY.txt](THIRD_PARTY.txt)).

---
