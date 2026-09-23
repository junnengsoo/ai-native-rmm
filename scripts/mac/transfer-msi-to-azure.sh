#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Transfer one MSI from a local macOS directory to an existing Azure Windows VM.

Usage:
  ./scripts/mac/transfer-msi-to-azure.sh \
    --resource-group RESOURCE_GROUP \
    --vm VM_NAME \
    --local-directory DIRECTORY \
    [--msi FILE_NAME] \
    [--destination 'C:\ProgramData\AI-Native-RMM\staging']

The script creates a private temporary Azure Storage account in the VM's region,
uses a 20-minute read-only HTTPS SAS to transfer the MSI, verifies SHA-256 on the
VM, and deletes the temporary storage account afterward. It does not install the
MSI. Azure CLI must already be signed in with permission to manage the target VM
and create/delete a Storage account in its resource group.
EOF
}

resource_group=
vm_name=
local_directory=
msi_name=
destination='C:\ProgramData\AI-Native-RMM\staging'

while [[ $# -gt 0 ]]; do
  case "$1" in
    --resource-group)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      resource_group=$2
      shift 2
      ;;
    --vm)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      vm_name=$2
      shift 2
      ;;
    --local-directory)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      local_directory=$2
      shift 2
      ;;
    --msi)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      msi_name=$2
      shift 2
      ;;
    --destination)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      destination=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown option: %s\n\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z $resource_group || -z $vm_name || -z $local_directory ]]; then
  usage >&2
  exit 2
fi
if [[ ! -d $local_directory ]]; then
  printf 'Local directory does not exist: %s\n' "$local_directory" >&2
  exit 1
fi
if ! command -v az >/dev/null 2>&1; then
  printf '%s\n' 'Azure CLI is required. Install it and run az login first.' >&2
  exit 1
fi
if ! az account show --output none >/dev/null 2>&1; then
  printf '%s\n' 'Azure CLI is not signed in. Run az login first.' >&2
  exit 1
fi

if [[ -n $msi_name ]]; then
  if [[ $msi_name == */* || $msi_name == *\\* || ! $msi_name =~ ^[A-Za-z0-9._-]+\.msi$ ]]; then
    printf '%s\n' '--msi must be a simple .msi file name containing only letters, numbers, dot, underscore, or hyphen.' >&2
    exit 2
  fi
  msi_path="$local_directory/$msi_name"
  [[ -f $msi_path ]] || { printf 'MSI not found: %s\n' "$msi_path" >&2; exit 1; }
else
  msi_files=()
  while IFS= read -r -d '' candidate; do
    msi_files+=("$candidate")
  done < <(find "$local_directory" -maxdepth 1 -type f -iname '*.msi' -print0)
  if [[ ${#msi_files[@]} -ne 1 ]]; then
    printf 'Expected exactly one MSI in %s; found %d. Use --msi FILE_NAME to select one.\n' \
      "$local_directory" "${#msi_files[@]}" >&2
    exit 1
  fi
  msi_path=${msi_files[0]}
  msi_name=$(basename "$msi_path")
  if [[ ! $msi_name =~ ^[A-Za-z0-9._-]+\.msi$ ]]; then
    printf 'MSI file name is not safe for remote transfer: %s\n' "$msi_name" >&2
    exit 1
  fi
fi

root=$(cd "$(dirname "$0")/../.." && pwd)
remote_script="$root/scripts/windows/azure-transfer-msi.ps1"
[[ -f $remote_script ]] || { printf 'Remote transfer helper is missing: %s\n' "$remote_script" >&2; exit 1; }

location=$(az vm show --resource-group "$resource_group" --name "$vm_name" --query location --output tsv)
[[ -n $location ]] || { printf '%s\n' 'Could not resolve the Azure VM location.' >&2; exit 1; }
power_state=$(az vm get-instance-view --resource-group "$resource_group" --name "$vm_name" \
  --query "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]" --output tsv)
if [[ $power_state != PowerState/running ]]; then
  printf 'Azure VM must be running; current state: %s\n' "${power_state:-unknown}" >&2
  exit 1
fi

expected_hash=$(shasum -a 256 "$msi_path" | awk '{print toupper($1)}')
storage_account="rmm$(uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-' | cut -c1-18)"
container=installer
blob_name=$msi_name
storage_created=false

cleanup() {
  unset AZURE_STORAGE_KEY AZURE_STORAGE_ACCOUNT 2>/dev/null || true
  if [[ $storage_created == true ]]; then
    printf '%s\n' 'Removing temporary Azure Storage account...'
    if ! az storage account delete --resource-group "$resource_group" --name "$storage_account" --yes --output none; then
      printf 'WARNING: could not remove temporary Storage account %s in resource group %s.\n' \
        "$storage_account" "$resource_group" >&2
    fi
  fi
}
trap cleanup EXIT

printf 'Creating temporary private Storage account %s...\n' "$storage_account"
az storage account create \
  --resource-group "$resource_group" \
  --name "$storage_account" \
  --location "$location" \
  --sku Standard_LRS \
  --kind StorageV2 \
  --https-only true \
  --min-tls-version TLS1_2 \
  --allow-blob-public-access false \
  --tags purpose=ai-native-rmm-demo-transfer \
  --output none
storage_created=true

storage_key=$(az storage account keys list --resource-group "$resource_group" --account-name "$storage_account" --query '[0].value' --output tsv)
[[ -n $storage_key ]] || { printf '%s\n' 'Could not obtain the temporary Storage account key.' >&2; exit 1; }
export AZURE_STORAGE_ACCOUNT=$storage_account
export AZURE_STORAGE_KEY=$storage_key
storage_key=
az storage container create \
  --account-name "$storage_account" \
  --name "$container" \
  --public-access off \
  --output none

printf 'Uploading %s...\n' "$msi_name"
az storage blob upload \
  --account-name "$storage_account" \
  --container-name "$container" \
  --name "$blob_name" \
  --file "$msi_path" \
  --overwrite false \
  --output none

expiry=$(date -u -v+20M '+%Y-%m-%dT%H:%MZ')
download_url=$(az storage blob generate-sas \
  --account-name "$storage_account" \
  --container-name "$container" \
  --name "$blob_name" \
  --permissions r \
  --expiry "$expiry" \
  --https-only \
  --full-uri \
  --output tsv)
unset AZURE_STORAGE_KEY AZURE_STORAGE_ACCOUNT
[[ -n $download_url ]] || { printf '%s\n' 'Could not create the temporary MSI download URL.' >&2; exit 1; }

printf 'Transferring MSI to Azure VM %s...\n' "$vm_name"
run_output=$(az vm run-command invoke \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --command-id RunPowerShellScript \
  --scripts @"$remote_script" \
  --parameters \
    "downloadUrl=$download_url" \
    "expectedHash=$expected_hash" \
    "fileName=$msi_name" \
    "destinationDirectory=$destination" \
  --query 'value[].message' \
  --output tsv)
download_url=

if [[ $run_output != *"MSI_TRANSFERRED $destination\\$msi_name"* ]]; then
  printf '%s\n' 'Azure Run Command did not report a completed MSI transfer.' >&2
  printf '%s\n' "$run_output" >&2
  exit 1
fi

printf 'Transferred and verified: %s\\%s\n' "$destination" "$msi_name"
printf 'SHA-256: %s\n' "$expected_hash"
