#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
demo_dir="$root/.demo"
env_file="$demo_dir/compose.env"
[[ -f "$env_file" && -f "$demo_dir/admin-key" && -f "$demo_dir/operator-key" && -f "$demo_dir/api-url" ]] || {
  printf '%s\n' 'Start the demo before approving an endpoint.' >&2
  exit 1
}
read -r -s -p 'Pairing code shown on Windows: ' pairing_code
printf '\n'
export RMM_ADMIN_KEY
RMM_ADMIN_KEY=$(<"$demo_dir/admin-key")
compose=(docker compose --project-name ai-native-rmm-demo --file "$root/compose.yaml" --env-file "$env_file")
response=$(printf '%s\n' "$pairing_code" | "${compose[@]}" exec -T -e RMM_ADMIN_KEY -e RMM_API_URL=http://127.0.0.1:8000 control-plane python -m control_plane.demo.approve)
device_id=$(printf '%s' "$response" | sed -n 's/.*"device_id": "\([^"]*\)".*/\1/p')
reachability=$(printf '%s' "$response" | sed -n 's/.*"reachability": "\([^"]*\)".*/\1/p')
[[ -n $device_id ]] || { printf '%s\n' 'Approval returned an unexpected response.' >&2; exit 1; }
printf '%s' "$device_id" > "$demo_dir/device-id"
chmod 600 "$demo_dir/device-id"
api_url=$(<"$demo_dir/api-url")
operator_key=$(<"$demo_dir/operator-key")
printf '{\n  "api_url": "%s",\n  "operator_api_key": "%s",\n  "device_id": "%s"\n}\n' \
  "$api_url" "$operator_key" "$device_id" > "$demo_dir/demo-connection.json"
chmod 600 "$demo_dir/demo-connection.json"
printf 'Endpoint %s is %s.\nCaller configuration: %s\n' "$device_id" "$reachability" "$demo_dir/demo-connection.json"
