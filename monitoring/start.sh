#!/usr/bin/env bash
set -euo pipefail

# Point to the HoneyMind log directory (default: ../logs relative to this script)
LOG_DIR="${HONEYMIND_LOG_DIR:-$(realpath "$(dirname "$0")/../logs")}"

if [[ ! -d "$LOG_DIR" ]]; then
  echo "[warning] Log directory not found: $LOG_DIR"
  echo "          Set HONEYMIND_LOG_DIR to your actual log directory."
  echo "          Creating it so the stack can start..."
  mkdir -p "$LOG_DIR"
fi

echo "Starting HoneyMind monitoring stack"
echo "  Log dir : $LOG_DIR"
echo "  Grafana : http://localhost:3000  (admin / honeymind)"
echo "  Loki    : http://localhost:3100"
echo "  Metrics : http://localhost:9091"
echo ""

HONEYMIND_LOG_DIR="$LOG_DIR" docker compose -f "$(dirname "$0")/docker-compose.yml" up --build "$@"
