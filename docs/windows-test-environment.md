# Existing Windows test environment

This is the trial's existing disposable test machine, not a deployment prerequisite for customers.

- Resource group: `rmm-trial-win11`
- VM: `rmm-win11`, region `eastus2`
- Windows 11 Enterprise 24H2; `Standard_D2as_v7`, 2 vCPU / 8 GiB
- Private address: `10.0.0.4`; no public IP
- Bastion: `rmm-bastion`, Developer SKU
- Automatic shutdown: 02:00 UTC daily
- .NET SDK 8.0.425 was installed at `C:\rmm-test-runtime` for the first agent slice.

## Access and testing

Use authenticated Azure CLI and Azure Run Command to deploy/launch tests. The existing [agent smoke guide](agent-harness.md) documents the runnable commands. Azure is only the test launcher; actual jobs use our agent protocol. Agent-only tests co-located with their harness do not demonstrate NAT connectivity.

Check state with `az vm show --resource-group rmm-trial-win11 --name rmm-win11 --show-details --query powerState`. Start the existing VM if needed with `az vm start --resource-group rmm-trial-win11 --name rmm-win11`.

For an interactive desktop, use Azure Portal Connect → Bastion. The administrator is `rmmadmin`; obtain its password from the owner's existing secure credential store, never from Git or logs. Do not add a public IP or expose RDP/SSH for tests.

The agreed control-plane direction is local Python/PostgreSQL plus a development HTTPS/WSS tunnel. The Windows agent initiates outbound communication; PostgreSQL stays private. There is no required Linux control-plane VM.

## Idle resources and cleanup

Avoid overlapping manual smoke runs on this VM. Deallocate when idle with `az vm deallocate --resource-group rmm-trial-win11 --name rmm-win11`; retained storage can still incur charges. Collect test evidence and trial artifacts before destructive cleanup. Do not delete the resource group until the trial is conclusively finished and cleanup is approved. See the [operations checklist](https://github.com/junnengsoo/ai-native-rmm/issues/2).
