#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Install a previously transferred Squash endpoint MSI on an Azure Windows VM.

Usage:
  ./scripts/mac/install-msi-on-azure.sh \
    --resource-group RESOURCE_GROUP \
    --vm VM_NAME \
    --endpoint wss://YOUR-CONTROL-PLANE/agent \
    [--msi SquashEndpointAgent.msi]

The MSI must already exist under C:\ProgramData\AI-Native-RMM\staging. The
script installs it silently through a temporary Managed Run Command with a
five-minute timeout, waits for the automatic Windows service and local status
file, then prints the pairing code.
EOF
}

resource_group=
vm_name=
endpoint=
msi_name=SquashEndpointAgent.msi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --resource-group) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; resource_group=$2; shift 2 ;;
    --vm) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; vm_name=$2; shift 2 ;;
    --endpoint) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; endpoint=$2; shift 2 ;;
    --msi) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; msi_name=$2; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z $resource_group || -z $vm_name || -z $endpoint ]]; then
  usage >&2
  exit 2
fi
if [[ ! $msi_name =~ ^[A-Za-z0-9._-]+\.msi$ ]]; then
  printf '%s\n' '--msi must be a simple .msi file name.' >&2
  exit 2
fi
if [[ ! $endpoint =~ ^wss://[A-Za-z0-9.-]+(:[0-9]{1,5})?/agent$ ]]; then
  printf '%s\n' '--endpoint must look like wss://host/agent.' >&2
  exit 2
fi
if ! command -v az >/dev/null 2>&1; then
  printf '%s\n' 'Azure CLI is required. Install it and run az login first.' >&2
  exit 1
fi
if ! az account show --output none >/dev/null 2>&1; then
  printf '%s\n' 'Azure CLI is not signed in. Run az login first.' >&2
  exit 1
fi

location=$(az vm show --resource-group "$resource_group" --name "$vm_name" --query location --output tsv)
[[ -n $location ]] || { printf '%s\n' 'Could not resolve the Azure VM location.' >&2; exit 1; }
power_state=$(az vm get-instance-view --resource-group "$resource_group" --name "$vm_name" \
  --query "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]" --output tsv)
if [[ $power_state != PowerState/running ]]; then
  printf 'Azure VM must be running; current state: %s\n' "${power_state:-unknown}" >&2
  exit 1
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
installer="$root/scripts/windows/Install-Agent.ps1"
[[ -f $installer ]] || { printf 'Installer helper is missing: %s\n' "$installer" >&2; exit 1; }
payload=$(base64 < "$installer" | tr -d '\n')
remote_script="\$ErrorActionPreference='Stop'; \$path=Join-Path \$env:TEMP ('install-squash-agent-'+[Guid]::NewGuid().ToString('N')+'.ps1'); try { [IO.File]::WriteAllBytes(\$path,[Convert]::FromBase64String('$payload')); & \$path -Endpoint '$endpoint' -MsiPath 'C:\ProgramData\AI-Native-RMM\staging\$msi_name' } finally { Remove-Item -LiteralPath \$path -Force -ErrorAction SilentlyContinue }"
run_command_name="rmm-install-$(uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-' | cut -c1-16)"
run_command_created=false

cleanup() {
  original_status=$?
  set +e
  if [[ $run_command_created == true ]]; then
    printf '%s\n' 'Removing temporary Azure Managed Run Command...'
    if ! az vm run-command delete \
      --resource-group "$resource_group" \
      --vm-name "$vm_name" \
      --name "$run_command_name" \
      --yes \
      --no-wait \
      --output none; then
      printf 'WARNING: could not remove temporary Managed Run Command %s.\n' "$run_command_name" >&2
    fi
  fi
  return "$original_status"
}
trap cleanup EXIT

run_command_created=true
az vm run-command create \
  --resource-group "$resource_group" \
  --vm-name "$vm_name" \
  --name "$run_command_name" \
  --location "$location" \
  --script "$remote_script" \
  --async-execution false \
  --timeout-in-seconds 300 \
  --tags purpose=ai-native-rmm-demo-install \
  --no-wait \
  --output none

execution_state=
for _ in {1..72}; do
  execution_state=$(az vm run-command show \
    --resource-group "$resource_group" \
    --vm-name "$vm_name" \
    --name "$run_command_name" \
    --instance-view \
    --query instanceView.executionState \
    --output tsv 2>/dev/null || true)
  case "$execution_state" in
    Succeeded|Failed|Canceled|TimedOut) break ;;
    *) sleep 5 ;;
  esac
done

output=$(az vm run-command show \
  --resource-group "$resource_group" \
  --vm-name "$vm_name" \
  --name "$run_command_name" \
  --instance-view \
  --query instanceView.output \
  --output tsv 2>/dev/null || true)
if [[ $execution_state != Succeeded ]]; then
  error_output=$(az vm run-command show \
    --resource-group "$resource_group" \
    --vm-name "$vm_name" \
    --name "$run_command_name" \
    --instance-view \
    --query instanceView.error \
    --output tsv 2>/dev/null || true)
  printf 'Managed Run Command did not succeed; state: %s\n' "${execution_state:-local_timeout}" >&2
  [[ -z $error_output ]] || printf '%s\n' "$error_output" >&2
  exit 1
fi
printf '%s\n' "$output"
if [[ $output != *AGENT_INSTALLED* ]]; then
  printf '%s\n' 'Azure Run Command did not report a completed installation.' >&2
  exit 1
fi
