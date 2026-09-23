param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64",
    [string]$OutputDirectory = "artifacts\windows-agent"
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$publish = Join-Path $repo "artifacts\publish\EndpointAgent"
$installerOut = Join-Path $repo $OutputDirectory

Remove-Item $publish, $installerOut -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory $publish, $installerOut | Out-Null

dotnet publish (Join-Path $repo "src\EndpointAgent") `
    -c $Configuration `
    -r $Runtime `
    --self-contained true `
    -p:PublishSingleFile=false `
    -p:PublishReadyToRun=false `
    -o $publish `
    --nologo
if ($LASTEXITCODE) { throw "publish_failed" }

$publishConstant = $publish.TrimEnd('\')
dotnet build (Join-Path $repo "installer\EndpointAgent.Installer.wixproj") `
    -c $Configuration `
    -p:PublishDir="$publishConstant" `
    -o $installerOut `
    --nologo
if ($LASTEXITCODE) { throw "installer_build_failed" }

$msi = Get-ChildItem $installerOut -Filter '*.msi' | Select-Object -First 1
if (-not $msi) { throw "installer_missing" }
Write-Output $msi.FullName
