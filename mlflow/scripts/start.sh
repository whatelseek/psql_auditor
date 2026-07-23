#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

mkdir -p "$ROOT/data/artifacts"

if [[ ! -f "$ROOT/.env" && -f "$ROOT/.env.example" ]]; then
  cp "$ROOT/.env.example" "$ROOT/.env"
  echo "Created $ROOT/.env from .env.example"
fi

docker compose --env-file "$ROOT/.env" -f "$ROOT/docker-compose.yml" up -d "$@"
docker compose --env-file "$ROOT/.env" -f "$ROOT/docker-compose.yml" ps

# shellcheck disable=SC1091
source "$ROOT/.env"
PORT="${MLFLOW_HOST_PORT:-5000}"
echo "MLflow UI: http://localhost:${PORT}"
echo "Tracking URI: http://localhost:${PORT}"
echo
echo "Agent integration (optional): set in repo .env then recreate agent:"
echo "  MLFLOW_ENABLED=true"
echo "  MLFLOW_TRACKING_URI=http://host.docker.internal:${PORT}"
echo "Drop tracking anytime: MLFLOW_ENABLED=false  (and/or $ROOT/scripts/stop.sh)"
