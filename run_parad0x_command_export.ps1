param(
  [string]$TargetPath = "$HOME\Desktop",
  [int]$Port = 8776,
  [string]$Workspace = "",
  [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if ([string]::IsNullOrWhiteSpace($Workspace) -and (Test-Path "$HOME\.openclaw")) {
  $Workspace = "$HOME\.openclaw"
}

if (-not (Test-Path ".venv")) {
  py -3 -m venv .venv
}

if (-not $SkipInstall) {
  .\.venv\Scripts\python.exe -m pip install --upgrade pip wheel setuptools
  .\.venv\Scripts\python.exe -m pip install -r requirements.txt
}

$args = @("tools\liquefy_desktop_viz.py", "live", $TargetPath, "--desktop", "--port", "$Port")
if (-not [string]::IsNullOrWhiteSpace($Workspace)) {
  $args += @("--workspace", $Workspace)
}

$serverJob = Start-Job -ScriptBlock {
  param($rootDir, $argv)
  Set-Location $rootDir
  & ".\.venv\Scripts\python.exe" @argv
} -ArgumentList $root, $args

Start-Process powershell -WindowStyle Hidden -ArgumentList @(
  "-NoProfile",
  "-ExecutionPolicy", "Bypass",
  "-Command",
  @"
$url = 'http://127.0.0.1:$Port'
for (`$i = 0; `$i -lt 120; `$i++) {
  try {
    Invoke-WebRequest -UseBasicParsing -Uri `$url -TimeoutSec 1 | Out-Null
    Start-Process `$url
    break
  } catch {
    Start-Sleep -Milliseconds 500
  }
}
"@
)

Wait-Job $serverJob | Out-Null
$jobOutput = Receive-Job $serverJob
if ($jobOutput) {
  $jobOutput
}
$job = Get-Job -Id $serverJob.Id
if ($job.State -eq "Failed") {
  throw "Parad0x Command server job failed."
}
