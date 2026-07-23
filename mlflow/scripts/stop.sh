#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

docker compose --env-file "$ROOT/.env" -f "$ROOT/docker-compose.yml" down "$@"
