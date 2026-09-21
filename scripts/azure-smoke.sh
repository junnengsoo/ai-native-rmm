#!/usr/bin/env bash
set -euo pipefail
# Existing authorized Windows VM only. RunCommand deploys/launches the test;
# execution dispatch happens over the real agent's outbound WSS connection.
cd "$(dirname "$0")/.."
bundle=$(mktemp -d /tmp/rmm-issue3.XXXXXX)
trap 'rm -f "$bundle/source.zip"; rmdir "$bundle"' EXIT
git ls-files -z --cached --others --exclude-standard -- src/EndpointAgent tests/ProtocolHarness scripts \
  | xargs -0 zip -q "$bundle/source.zip"
payload=$(base64 < "$bundle/source.zip" | tr -d '\n')
script="\$ErrorActionPreference='Stop'; \$root=Join-Path \$env:TEMP ('rmm-issue3-'+[Guid]::NewGuid().ToString('N')); New-Item -ItemType Directory \$root | Out-Null; [IO.File]::WriteAllBytes((Join-Path \$root 'source.zip'),[Convert]::FromBase64String('$payload')); Expand-Archive (Join-Path \$root 'source.zip') (Join-Path \$root 'source'); & (Join-Path \$root 'source/scripts/windows-smoke.ps1')"
output=$(az vm run-command invoke --resource-group rmm-trial-win11 --name rmm-win11 \
  --command-id RunPowerShellScript --scripts "$script" --query 'value[].message' -o tsv)
printf '%s\n' "$output"
# Azure's extension can report a successful invocation for a failing script.
# Require the suite's explicit completion marker, not the CLI exit status alone.
[[ "$output" == *"RMM_SUITE_PASSED"* ]]
