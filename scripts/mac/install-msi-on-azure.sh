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
script installs it silently through Azure Run Command, waits for the automatic
Windows service and local status file, then prints the pairing code.
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

root=$(cd "$(dirname "$0")/../.." && pwd)
installer="$root/scripts/windows/Install-Agent.ps1"
[[ -f $installer ]] || { printf 'Installer helper is missing: %s\n' "$installer" >&2; exit 1; }
payload=$(base64 < "$installer" | tr -d '\n')
remote_script="\$ErrorActionPreference='Stop'; \$path=Join-Path \$env:TEMP ('install-squash-agent-'+[Guid]::NewGuid().ToString('N')+'.ps1'); try { [IO.File]::WriteAllBytes(\$path,[Convert]::FromBase64String('$payload')); & \$path -Endpoint '$endpoint' -MsiPath 'C:\ProgramData\AI-Native-RMM\staging\$msi_name' } finally { Remove-Item -LiteralPath \$path -Force -ErrorAction SilentlyContinue }"

output=$(az vm run-command invoke \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --command-id RunPowerShellScript \
  --scripts "$remote_script" \
  --query 'value[].message' \
  --output tsv)
printf '%s\n' "$output"
if [[ $output != *AGENT_INSTALLED* ]]; then
  printf '%s\n' 'Azure Run Command did not report a completed installation.' >&2
  exit 1
fi
