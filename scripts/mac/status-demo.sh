#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
env_file="$root/.demo/compose.env"
[[ -f "$env_file" ]] || { printf '%s\n' 'No demo environment exists.'; exit 1; }
docker compose --project-name ai-native-rmm-demo --file "$root/compose.yaml" --env-file "$env_file" --profile tunnel ps
[[ -f "$root/.demo/api-url" ]] && printf 'API URL: %s\n' "$(<"$root/.demo/api-url")"
[[ -f "$root/.demo/device-id" ]] && printf 'Device ID: %s\n' "$(<"$root/.demo/device-id")"
