#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
demo_dir="$root/.demo"
env_file="$demo_dir/compose.env"
if [[ -f "$env_file" ]]; then
  docker compose --project-name ai-native-rmm-demo --file "$root/compose.yaml" --env-file "$env_file" --profile tunnel down --volumes --remove-orphans
fi
rm -rf "$demo_dir"
printf '%s\n' 'Removed only the ai-native-rmm-demo database and local demo credentials.'
exec "$root/scripts/mac/start-demo.sh" "$@"
