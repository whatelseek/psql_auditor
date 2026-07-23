#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

docker compose --env-file "$ROOT/.env" -f "$ROOT/docker-compose.yml" ps
echo
# shellcheck disable=SC1091
source "$ROOT/.env"
PORT="${MLFLOW_HOST_PORT:-5000}"
if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
  echo "Health: OK (http://127.0.0.1:${PORT}/health)"
else
  echo "Health: unavailable (http://127.0.0.1:${PORT}/health)"
  exit 1
fi
