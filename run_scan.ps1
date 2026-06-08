param(
    [string]$Path = ".",
    [string]$Output = "",
    [int]$MaxWorkers = 4,
    [int]$RecursiveDepth = 5,
    [switch]$TrivyOnly,
    [switch]$DryRun,
    [switch]$NoDashboard,
    [switch]$HideCommands,
    [switch]$NoColor
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EntryPoint = Join-Path $ScriptDir "autoscan.py"

if (-not (Test-Path $EntryPoint)) {
    Write-Host "[ERROR] autoscan.py not found: $EntryPoint" -ForegroundColor Red
    exit 1
}

$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
    $pythonCmd = Get-Command python3 -ErrorAction SilentlyContinue
}
if (-not $pythonCmd) {
    Write-Host "[ERROR] python/python3 not found in PATH" -ForegroundColor Red
    exit 1
}

$argsList = @(
    $EntryPoint,
    $Path,
    "--max-workers", "$MaxWorkers",
    "--recursive-depth", "$RecursiveDepth"
)

if ($Output -ne "") {
    $argsList += @("--output", $Output)
}
if ($TrivyOnly) {
    $argsList += "--trivy-only"
}
if ($DryRun) {
    $argsList += "--dry-run"
}
if ($NoDashboard) {
    $argsList += "--no-dashboard"
}
if ($HideCommands) {
    $argsList += "--hide-commands"
}
if ($NoColor) {
    $argsList += "--no-color"
}

& $pythonCmd.Source @argsList
exit $LASTEXITCODE
