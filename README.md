# DataTrap - Data Driven AI-based Honeypot

DataTrap is an extensible honeypot system that emulates realistic behavior across SSH, HTTP/HTTPS, MySQL, PostgreSQL, Redis, Telnet, and generic TCP protocols. Designed to simulate web applications, IoT devices, and databases, DataTrap combines recorded payloads with LLM-based response generation to closely mimic real application behavior.

When an attacker’s request matches the dataset, the recorded response is returned directly. When no match is found, an LLM generates a realistic response that is logged for review and future inclusion in the dataset. This continuous enrichment process keeps the system effective against emerging threats.

DataTrap is open-source and welcomes community contributions. Deployment is simplified through a Docker container, enabling users to run the honeypot system in any environment with minimal setup.

---

## Supported Protocols

| Protocol   | Example Targets           | Key Capabilities                                                  |
|------------|---------------------------|-------------------------------------------------------------------|
| SSH        | Alpine Linux, Busybox     | Shell emulation, fake filesystem, file download simulation        |
| HTTP/HTTPS | Boa Server, phpMyAdmin    | All HTTP methods, session cookies, dispatcher routing             |
| MySQL      | MySQL 5.7 / 8.0           | Handshake, authentication, SQL query processing                   |
| PostgreSQL | PostgreSQL                | Startup messages, authentication, queries, prepared statements    |
| Redis      | Redis                     | RESP protocol, multi-database (SELECT), SET/GET/DEL/KEYS/AUTH     |
| Telnet     | D-Link routers            | Banner, login prompts, session timeout                            |
| TCP        | Generic services          | Action-based query/response on any TCP port                       |

---

## Features

* Emulates 7 protocols with realistic request/response behavior
* LLM fallback (via AWS Bedrock) for unknown requests, with rate limiting per visitor
* Dataset-first design: JSONL files with dynamic placeholders (`${user}`, `${host}`, etc.)
* Dispatcher mode: routes connections to multiple backend honeypots on a single port ([docs](docs/dispatcher.md))
* Fake filesystem: compressed JSONL definitions loaded into SQLite for shell commands (ls, cd, mkdir, wget)
* Chained data handlers: file downloads → fake filesystem → dataset lookup → LLM fallback
* Session tracking with UUIDs, client IP logging, and per-session state
* JSON-formatted logging with honeypot metadata, compatible with fluent-bit and CloudWatch
* Docker-based deployment with multi-architecture support (amd64, arm64)

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Dispatcher                        │
│         (optional single-port routing)              │
└──────────┬──────────┬──────────┬────────────────────┘
           │          │          │
     ┌─────▼───┐ ┌───▼────┐ ┌──▼──────┐
     │   SSH   │ │  HTTP  │ │  MySQL  │  ...
     │ Handler │ │ Handler│ │ Handler │
     └────┬────┘ └───┬────┘ └────┬────┘
          │          │           │
     ┌────▼──────────▼───────────▼────┐
     │      Data Handler Chain        │
     │  FileDownload → FakeFS →       │
     │  Dataset Lookup → LLM Fallback │
     └────────────┬───────────────────┘
                  │
     ┌────────────▼───────────────────┐
     │   Dataset (JSONL / SQLite)     │
     │   + LLM Engine (AWS Bedrock)   │
     └────────────────────────────────┘
```

* **Protocol Handlers**: Implement protocol-specific logic (SSH via Paramiko, HTTP via Flask, MySQL via mysql-mimic, PostgreSQL native protocol, Redis RESP, Telnet via telnetlib3)
* **Data Handler Chain**: Processes requests through a configurable pipeline — file downloads, fake filesystem, dataset lookup, and LLM fallback
* **Dataset & Lookup Engine**: Maps incoming requests to recorded payloads in JSONL files backed by SQLite
* **LLM Engine**: Generates realistic responses for unknown requests using AWS Bedrock with configurable system prompts and per-visitor rate limiting
* **Dispatcher**: Routes connections to different honeypots based on traffic inspection or LLM-assisted classification, with sticky session support
* **Logging**: Tracks all interactions with session IDs, client IPs, and honeypot metadata in structured JSON format

---

## Dataset

The dataset powers DataTrap’s response generation. Each JSONL file contains request-response pairs for a specific application and version:

* **request**: the attacker’s input
* **response**: the emulated reply
* Optional placeholders like `${user}` or `${host}` for dynamic substitution
* Context-aware fields (e.g., current working directory, database state)

Datasets can be layered — for example, a general MySQL dataset combined with a version-specific dataset for MySQL 5.7 behavior.

**Known requests** are matched and returned directly. **Unknown requests** are handled by the LLM and logged separately for review and future inclusion.

### Example

```json
{"request": "SELECT version()", "response": "5.7.33-0ubuntu0.16.04.1"}
{"request": "DROP TABLE users;", "response": "Error: DROP command denied to user ‘${user}’@’${host}’ for table ‘users’"}
```

For more details on dataset formats, see [data usage](docs/data_usage.md) and [SQLite data handling](docs/sqlite_data_handling.md).

---

## Configuration

Each honeypot is defined by a `config.json` in its own directory. The main fields are:

| Field              | Description                                           |
|--------------------|-------------------------------------------------------|
| `type`             | Protocol type: `ssh`, `http`, `mysql`, `postgresql`, `redis`, `telnet`, `tcp` |
| `port`             | Port to listen on                                     |
| `data_file`        | Path to JSONL dataset (e.g., `data.jsonl`)            |
| `model_id`         | LLM model ID for Bedrock (e.g., `anthropic.claude-3-5-sonnet-20240620-v1:0`) |
| `system_prompt`    | Instructions guiding LLM responses                    |
| `name`             | Display name for logging                              |
| `prompt_template`  | Shell prompt format with `${{username}}`, `${{cwd}}` placeholders (SSH/Telnet) |
| `fs_file`          | Path to compressed fake filesystem (e.g., `fs_alpine.jsonl.gz`) |
| `is_dispatcher`    | Enable dispatcher mode (HTTP)                         |

### Example: SSH honeypot

```json
{
  "type": "ssh",
  "name": "Alpine Linux",
  "port": 2222,
  "data_file": "data.jsonl",
  "fs_file": "fs_alpine.jsonl.gz",
  "prompt_template": "${{username}}@alpine:${{cwd}}$ ",
  "model_id": "anthropic.claude-3-5-sonnet-20240620-v1:0",
  "system_prompt": "You are a terminal on Alpine Linux. Respond only with terminal output."
}
```

For the full configuration schema, see [honeypot configuration](docs/honeypot_configuration.md).

---

## Installation

DataTrap is packaged as a Docker image for quick and reproducible deployment.

### Pull and run

```sh
docker pull ghcr.io/thalesgroup/dd-honeypot
```

```sh
docker run -d \
  -p 80:80 -p 2222:2222 -p 3306:3306 \
  -v /your/honeypot/folder:/data/honeypot \
  ghcr.io/thalesgroup/dd-honeypot
```

The container starts honeypot services based on the configurations found in `/data/honeypot`. Each subdirectory should contain a `config.json` defining one honeypot instance.

### AWS EC2 deployment

1. Create an instance role with permissions for CloudWatch Logs and Bedrock
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
  ghcr.io/thalesgroup/dd-honeypot
```

### LLM configuration

DataTrap uses AWS Bedrock for LLM-based response generation. Provide AWS credentials via environment variables or the `config/aws.env.list` file:

```
AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY
AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY
AWS_REGION=us-east-1
```

---

## Documentation

| Topic | Link |
|-------|------|
| Honeypot configuration schema | [docs/honeypot_configuration.md](docs/honeypot_configuration.md) |
| Dispatcher (multi-honeypot routing) | [docs/dispatcher.md](docs/dispatcher.md) |
| Fake filesystem guide | [docs/fakefs_json_guide.md](docs/fakefs_json_guide.md) |
| Dataset usage | [docs/data_usage.md](docs/data_usage.md) |
| SQLite data handling | [docs/sqlite_data_handling.md](docs/sqlite_data_handling.md) |
| Redis honeypot | [docs/redis_honeypot.md](docs/redis_honeypot.md) |
| Logging & fluent-bit | [docs/logging-readme.md](docs/logging-readme.md) |
| Multi-IP networking | [docs/networking-readme.md](docs/networking-readme.md) |

---

## Contributing

We welcome community contributions — new honeypot types, protocol handlers, datasets, system prompts, and test cases.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup instructions, testing guidelines, and the PR checklist.

---

## Licensing

DataTrap is distributed under the [Apache 2.0 License](LICENSE.md).
It depends on modules licensed under their own open-source licenses (see [THIRD_PARTY.txt](THIRD_PARTY.txt)).

---

