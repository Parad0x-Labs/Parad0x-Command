param(
  [string]$RepoUrl = "https://github.com/Parad0x-Labs/Parad0x-Command.git",
  [string]$DestRoot = "$HOME/Desktop",
  [string]$FolderName = "Parad0x Command",
  [int]$Port = 8776,
  [string]$Workspace = "",
  [switch]$SkipInstall,
  [switch]$NoLaunch
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Workspace) -and (Test-Path "$HOME\.openclaw")) {
  $Workspace = "$HOME\.openclaw"
}

$installDir = Join-Path $DestRoot $FolderName
New-Item -ItemType Directory -Force -Path $DestRoot | Out-Null

if (-not (Test-Path (Join-Path $installDir ".git"))) {
  git clone $RepoUrl $installDir
}

Set-Location $installDir

if (-not (Test-Path ".venv")) {
  py -3 -m venv .venv
}

if (-not $SkipInstall) {
  .\.venv\Scripts\python.exe -m pip install --upgrade pip wheel setuptools
  .\.venv\Scripts\python.exe -m pip install -r requirements.txt
}

$envFile = Join-Path $installDir ".parad0x_command.env.ps1"
@"
`$TargetPath = "$HOME\Desktop"
`$Port = $Port
`$Workspace = "$Workspace"
"@ | Set-Content -Encoding UTF8 $envFile

$serverScript = Join-Path $installDir "run_parad0x_command_server.ps1"
@'
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $root ".parad0x_command.env.ps1")
if ([string]::IsNullOrWhiteSpace($Workspace) -and (Test-Path "$HOME\.openclaw")) {
  $Workspace = "$HOME\.openclaw"
}
$args = @((Join-Path $root "tools\liquefy_desktop_viz.py"), "live", $TargetPath, "--desktop", "--port", "$Port")
if (-not [string]::IsNullOrWhiteSpace($Workspace)) {
  $args += @("--workspace", $Workspace)
}
& (Join-Path $root ".venv\Scripts\python.exe") @args
'@ | Set-Content -Encoding UTF8 $serverScript

$launchScript = Join-Path $installDir "launch_parad0x_command.ps1"
@'
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $root ".parad0x_command.env.ps1")
$url = "http://127.0.0.1:$Port"
try {
  Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 1 | Out-Null
} catch {
  Start-Process powershell -WindowStyle Hidden -ArgumentList "-NoProfile","-ExecutionPolicy","Bypass","-File",(Join-Path $root "run_parad0x_command_server.ps1")
  Start-Sleep -Seconds 2
}
Start-Process $url
'@ | Set-Content -Encoding UTF8 $launchScript

$desktopCmd = Join-Path $DestRoot "Parad0x Command.cmd"
@"
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File `"$launchScript`"
"@ | Set-Content -Encoding ASCII $desktopCmd

Write-Host "Parad0x Command installed to: $installDir"
Write-Host "Launcher created at: $desktopCmd"
if ($Workspace) {
  Write-Host "Workspace autodetected/configured: $Workspace"
} else {
  Write-Host "Workspace: none (standalone mode)"
}

if (-not $NoLaunch) {
  & powershell -NoProfile -ExecutionPolicy Bypass -File $launchScript
}
