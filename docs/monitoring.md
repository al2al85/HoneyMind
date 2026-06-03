# Dashboard and Monitoring

HoneyMind has two local analysis surfaces:

- The HoneyMind web dashboard, an internal analysis tool for security teams.
- The Grafana monitoring stack, an operational view backed by Loki and Prometheus.

Neither of these services is a honeypot. The supported honeypot surface is currently SSH. The dashboard and Grafana consume local HoneyMind logs and derived IOC/campaign data.

HoneyMind is based on the original [ThalesGroup dd-honeypot](https://github.com/ThalesGroup/dd-honeypot) project and preserves the original license and attribution.

## Data Flow

```text
SSH honeypot
  -> local JSONL logs
  -> ioc-writer
  -> iocs.db
  -> ioc-api
  -> HoneyMind web dashboard

local JSONL logs
  -> monitoring/log_processor
  -> Loki + Prometheus
  -> Grafana
```

## HoneyMind Web Dashboard

The web dashboard is served by the `website` service in `docker-compose.yml`. It is designed for investigation and business-oriented analysis rather than raw infrastructure monitoring.

Current dashboard areas include:

- Dashboard overview with attack totals, unique IPs, active campaigns, command volume, and activity charts.
- Source map for attacker origin visualization.
- Campaigns split between active and inactive sections.
- Campaign detail pages with sessions, IOC, commands, reports, and campaign context.
- Commands page with usage ranking, search, command detail panel, and clickable related campaigns.
- IOC page for IPs, URLs, domains, and files.
- LLM cost page backed by the local usage database when usage logging is enabled.

The dashboard reads:

- `/api/v1/iocs/*` from `ioc-api`.
- `/api/v1/llm-cost` from `ioc-api`.
- `/loki/*` through the website Nginx proxy when the monitoring stack is available.

By default in the provided compose file:

```text
http://localhost:44806
```

## IOC Writer and API

The dashboard depends on two backend services:

| Service | Role |
| ------- | ---- |
| `ioc-writer` | Reads local JSONL logs, extracts IOC, updates sessions, detects campaigns, and stores derived data in SQLite. |
| `ioc-api` | Serves the dashboard API, campaign reports, IOC, command rankings, activity, and LLM cost summaries. |

Important environment variables:

| Variable | Default in compose | Purpose |
| -------- | ------------------ | ------- |
| `LOG_DIR` | `/data/honeypot/logs` | Directory containing local JSONL logs. |
| `IOC_DB` | `/data/honeypot/logs/iocs.db` | SQLite database used by the IOC pipeline and dashboard API. |
| `IOC_POLL_INTERVAL` | `15` | Log polling interval in seconds. |
| `IOC_CAMPAIGN_INTERVAL` | `120` | Campaign detection interval in seconds. |

## Campaign Detection

Campaigns are derived from observed sessions. HoneyMind currently considers:

- Source IP and `/24` subnet overlap.
- ASN overlap when enrichment data is available.
- SSH HASSH fingerprints.
- Command sequence fingerprints.
- HTTP User-Agent fingerprints for inherited or future HTTP workflows.
- Shared commands and overlapping time windows.

Candidates that strongly overlap in session membership are consolidated before being exposed in the dashboard. This avoids creating several separate campaigns when multiple signals point to the same attacker workflow.

Campaign status is based on the stored campaign status or its end time. Campaigns without a known end time are treated as active; campaigns with an older end time are shown as inactive/closed.

## Grafana Monitoring

The monitoring stack lives under `monitoring/` and is optional:

| Service | Purpose |
| ------- | ------- |
| Loki | Stores structured log streams for Grafana. |
| Prometheus | Stores metrics from the log processor. |
| Grafana | Displays operational dashboards. |
| log-processor | Reads HoneyMind JSONL logs, sends events to Loki, and exposes metrics. |

Start the monitoring stack:

```sh
docker compose -f monitoring/docker-compose.yml up -d
```

Default local URLs:

```text
Grafana:    http://localhost:3000
Prometheus: http://localhost:9091
Loki:       http://localhost:3100
```

Default Grafana credentials in the development compose file:

```text
username: admin
password: honeymind
```

Change these values before exposing Grafana beyond a local development machine.

## Running the Full Local Stack

The main compose file expects the shared monitoring network to exist. Starting the monitoring compose file first creates it:

```sh
docker compose -f monitoring/docker-compose.yml up -d
docker compose up -d
```

If you want to run the dashboard without Grafana, create the network manually before starting the main compose stack:

```sh
docker network create honeymind-monitoring
docker compose up -d honeymind ioc-writer ioc-api website
```

## Security Notes

- The web dashboard and Grafana are internal tools. Do not expose them directly to the public internet without authentication, TLS, and network controls.
- Local JSONL logs can contain attacker commands, credentials attempted against the honeypot, payload URLs, and LLM prompts/responses.
- Remote LLM providers receive honeypot interaction data when LLM fallback is used. Review privacy, legal, and operational requirements before sending attacker traffic to third-party APIs.
