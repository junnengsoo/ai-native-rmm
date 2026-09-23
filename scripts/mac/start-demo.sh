#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
demo_dir="$root/.demo"
env_file="$demo_dir/compose.env"
mode=tunnel
public_url=

while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-url)
      [[ $# -ge 2 ]] || { printf '%s\n' '--public-url requires an HTTPS URL' >&2; exit 2; }
      mode=public
      public_url=${2%/}
      shift 2
      ;;
    --local-only)
      mode=local
      shift
      ;;
    *)
      printf 'Unknown option: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

if [[ $mode == public && $public_url != https://* ]]; then
  printf '%s\n' '--public-url must use HTTPS.' >&2
  exit 2
fi
if ! docker compose version >/dev/null 2>&1; then
  printf '%s\n' 'Docker Desktop or Docker Engine with Compose is required.' >&2
  exit 1
fi

mkdir -p "$demo_dir"
chmod 700 "$demo_dir"
if [[ ! -f "$env_file" ]]; then
  if ! command -v openssl >/dev/null 2>&1; then
    printf '%s\n' 'OpenSSL is required to generate the local demo database password.' >&2
    exit 1
  fi
  password=$(openssl rand -base64 36 | tr '/+' '_-' | tr -d '=\n')
  printf 'RMM_POSTGRES_PASSWORD=%s\nRMM_HTTP_PORT=0\n' "$password" > "$env_file"
  chmod 600 "$env_file"
fi

compose=(docker compose --project-name ai-native-rmm-demo --file "$root/compose.yaml" --env-file "$env_file")
"${compose[@]}" up -d --build --wait --wait-timeout 60 database control-plane
published=$("${compose[@]}" port control-plane 8000)
local_url="http://$published"

admin_file="$demo_dir/admin-key"
operator_file="$demo_dir/operator-key"
if [[ ! -f "$admin_file" || ! -f "$operator_file" ]]; then
  bootstrap=$("${compose[@]}" exec -T control-plane python -m control_plane.demo.setup)
  admin_key=$(printf '%s' "$bootstrap" | sed -n 's/.*"admin_key": "\([^"]*\)".*/\1/p')
  operator_key=$(printf '%s' "$bootstrap" | sed -n 's/.*"operator_api_key": "\([^"]*\)".*/\1/p')
  if [[ -z $admin_key || -z $operator_key ]]; then
    printf '%s\n' 'Demo credential bootstrap returned an unexpected response.' >&2
    exit 1
  fi
  printf '%s' "$admin_key" > "$admin_file"
  printf '%s' "$operator_key" > "$operator_file"
  chmod 600 "$admin_file" "$operator_file"
fi

case "$mode" in
  tunnel)
    "${compose[@]}" --profile tunnel up -d tunnel
    public_url=
    for _ in {1..30}; do
      public_url=$("${compose[@]}" --profile tunnel logs --no-color tunnel 2>/dev/null | grep -Eo 'https://[-a-z0-9]+\.trycloudflare\.com' | tail -1 || true)
      [[ -n $public_url ]] && break
      sleep 1
    done
    if [[ -z $public_url ]]; then
      printf '%s\n' 'The development tunnel did not publish a URL. Inspect: docker compose -p ai-native-rmm-demo logs tunnel' >&2
      exit 1
    fi
    ;;
  local)
    public_url=$local_url
    "${compose[@]}" --profile tunnel stop tunnel >/dev/null 2>&1 || true
    ;;
  public)
    "${compose[@]}" --profile tunnel stop tunnel >/dev/null 2>&1 || true
    ;;
esac

printf '%s' "$public_url" > "$demo_dir/api-url"
chmod 600 "$demo_dir/api-url"
operator_key=$(<"$operator_file")
device_id=
[[ -f "$demo_dir/device-id" ]] && device_id=$(<"$demo_dir/device-id")
printf '{\n  "api_url": "%s",\n  "operator_api_key": "%s",\n  "device_id": %s\n}\n' \
  "$public_url" "$operator_key" "$(if [[ -n $device_id ]]; then printf '"%s"' "$device_id"; else printf 'null'; fi)" \
  > "$demo_dir/demo-connection.json"
chmod 600 "$demo_dir/demo-connection.json"

printf '\nAI-Native RMM demo is ready.\n\n'
printf 'Local API: %s\n' "$local_url"
printf 'API URL:  %s\n' "$public_url"
printf 'OpenAPI:  %s/docs\n' "$public_url"
printf 'Caller configuration: %s\n' "$demo_dir/demo-connection.json"
if [[ -z $device_id ]]; then
  printf '\nInstall the bundled MSI on Windows with CONTROL_PLANE_URL=%s\n' "$public_url"
  printf 'Then run ./demo.sh approve on this machine.\n'
else
  printf 'Device ID: %s\n' "$device_id"
fi
