#!/bin/sh
# Avvio locale dietro tunnel o proxy. Ascolta solo su 127.0.0.1.
# Uso: UNIVERSE_BOT_TOKENS_FILE=/percorso/tokens.json ./scripts/run_local.sh
set -eu
cd "$(dirname "$0")/.."
PORT="${PORT:-8080}"
export UNIVERSE_DRY_RUN="${UNIVERSE_DRY_RUN:-1}"
export UNIVERSE_ENABLE_DOCS="${UNIVERSE_ENABLE_DOCS:-0}"
export UNIVERSE_REQUIRE_TLS="${UNIVERSE_REQUIRE_TLS:-1}"
export UNIVERSE_CONFIGS_DIR="${UNIVERSE_CONFIGS_DIR:-configs}"
# Non esportare UNIVERSE_ALLOW_LIVE.
exec uvicorn universe.app:app --host 127.0.0.1 --port "$PORT" --no-server-header --proxy-headers --forwarded-allow-ips=127.0.0.1
