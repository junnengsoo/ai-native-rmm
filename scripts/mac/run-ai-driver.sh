#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
config=${RMM_DEMO_CONNECTION_FILE:-"$root/.demo/demo-connection.json"}
env_file="$root/.demo/compose.env"

if [[ ! -f "$config" || ! -f "$env_file" ]]; then
  printf 'Caller configuration not found: %s\n' "$config" >&2
  printf 'Complete demo setup and endpoint approval first.\n' >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  printf 'Docker Compose is required on the control-plane machine.\n' >&2
  exit 1
fi
if [[ -z ${OPENAI_API_KEY:-} ]]; then
  read -r -s -p 'OpenAI API key (not saved): ' OPENAI_API_KEY
  printf '\n'
  export OPENAI_API_KEY
fi

driver_args=(--config /app/demo-connection.json --base-url http://control-plane:8000)
if [[ ${1:-} == --once ]]; then
  if [[ $# -ne 2 || -z $2 ]]; then
    printf 'Usage: %s --once "diagnostic question"\n' "$0" >&2
    exit 2
  fi
  driver_args+=("$2")
elif [[ $# -eq 0 ]]; then
  driver_args+=(--interactive)
else
  driver_args+=("$@")
fi

docker compose \
  --project-name ai-native-rmm-demo \
  --file "$root/compose.yaml" \
  --env-file "$env_file" \
  run --rm --no-deps \
  --volume "$config:/app/demo-connection.json:ro" \
  --env OPENAI_API_KEY \
  control-plane \
  python -m control_plane.openai_driver "${driver_args[@]}"
