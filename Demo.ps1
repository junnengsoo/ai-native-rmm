$ErrorActionPreference = 'Stop'
$Command = if ($args.Count) { [string]$args[0] } else { 'help' }
$CommandArguments = if ($args.Count -gt 1) { [string[]]$args[1..($args.Count - 1)] } else { @() }
$scripts = Join-Path $PSScriptRoot 'scripts\windows'
$target = switch ($Command.ToLowerInvariant()) {
    'start'   { 'Start-Demo.ps1' }
    'approve' { 'Approve-Device.ps1' }
    'ai'      { 'Run-AIDriver.ps1' }
    'status'  { 'Status-Demo.ps1' }
    'stop'    { 'Stop-Demo.ps1' }
    'reset'   { 'Reset-Demo.ps1' }
    'help'    { $null }
    '-h'      { $null }
    '--help'  { $null }
    default   { throw "Unknown command '$Command'. Run .\Demo.ps1 help for usage." }
}

if (-not $target) {
    @'
AI-Native RMM reviewer demo

Usage: .\Demo.ps1 COMMAND [OPTIONS]

Commands:
  start      Create or resume the control plane; starts a tunnel by default
  approve    Prompt for the pairing code and generate caller configuration
  ai         Run the interactive AI diagnostic console
  status     Show control-plane and endpoint status without changing state
  stop       Stop services while preserving state and credentials
  reset      Delete only this demo's state and start a fresh environment

Examples:
  .\Demo.ps1 start
  .\Demo.ps1 start -LocalOnly
  .\Demo.ps1 start -PublicUrl https://rmm.example.com
  .\Demo.ps1 approve
  .\Demo.ps1 ai
  .\Demo.ps1 ai -Once "Why can this machine not reach the file server?"
'@ | Write-Host
    exit 0
}

& (Join-Path $scripts $target) @CommandArguments
exit $LASTEXITCODE
