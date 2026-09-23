#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
env_file="$root/.demo/compose.env"
[[ -f "$env_file" ]] || { printf '%s\n' 'No demo environment exists.'; exit 0; }
docker compose --project-name ai-native-rmm-demo --file "$root/compose.yaml" --env-file "$env_file" --profile tunnel down
printf '%s\n' 'Demo stopped. Database and credentials were preserved.'
