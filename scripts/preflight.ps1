[CmdletBinding()]
param(
    [switch]$RequireGeminiKey
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Fail([string]$Message) {
    Write-Error $Message
    exit 1
}

Write-Output "AEGIS preflight: $root"

$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    Fail "Missing Python virtual environment: $python"
}

& $python -c "import fastapi, uvicorn, pandas, pyarrow, langgraph, langchain_google_genai"
if ($LASTEXITCODE -ne 0) {
    Fail "Required backend imports failed. Install with .\.venv\Scripts\python.exe -m pip install -r requirements.txt"
}
Write-Output "PASS Python environment and backend imports"

$node = Get-Command node.exe -ErrorAction SilentlyContinue
$npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not $node) {
    Fail "node.exe is not on PATH. Install Node.js 20 LTS or newer LTS."
}
if (-not $npm) {
    Fail "npm.cmd is not on PATH. Install Node.js 20 LTS or newer LTS."
}
Write-Output "PASS Node.js and npm are available"

$packageJson = Join-Path $root "frontend\package.json"
$packageLock = Join-Path $root "frontend\package-lock.json"
$nodeModules = Join-Path $root "frontend\node_modules"
if (-not (Test-Path -LiteralPath $packageJson -PathType Leaf)) {
    Fail "Missing frontend\package.json."
}
if (-not (Test-Path -LiteralPath $packageLock -PathType Leaf)) {
    Fail "Missing frontend\package-lock.json."
}
if (-not (Test-Path -LiteralPath $nodeModules -PathType Container)) {
    Fail "Frontend dependencies are not installed. Run 'Set-Location frontend; npm.cmd ci'."
}
Write-Output "PASS frontend manifest, lockfile, and node_modules"

$envFile = Join-Path $root ".env"
$envConfigured = $false
if (Test-Path -LiteralPath $envFile -PathType Leaf) {
    $envConfigured = @(Get-Content -LiteralPath $envFile |
        Where-Object { $_ -match '^\s*GOOGLE_API_KEY\s*=\s*["'']?[^"'']+\s*["'']?\s*$' }).Count -gt 0
}
if ($RequireGeminiKey -and -not $envConfigured) {
    Fail "GOOGLE_API_KEY is not configured in .env. The value was not printed."
}
if ($envConfigured) {
    Write-Output "PASS local Gemini credential configuration detected (value hidden)"
} else {
    Write-Warning "GOOGLE_API_KEY is not configured; safe checks can continue, live Gemini runs cannot."
}

$datasetDirectory = Join-Path $root "data\raw"
$datasets = @(Get-ChildItem -LiteralPath $datasetDirectory -File -Filter "*.parquet" -ErrorAction SilentlyContinue)
if ($datasets.Count -eq 0) {
    Fail "No Parquet datasets were found under data\raw."
}
foreach ($dataset in $datasets) {
    $stream = [System.IO.File]::OpenRead($dataset.FullName)
    $stream.Dispose()
}
Write-Output ("PASS readable datasets: " + $datasets.Count)

foreach ($port in @(8000, 3000)) {
    $listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($listener) {
        Write-Output "INFO port $port is occupied; reuse only if the service is healthy."
    } else {
        Write-Output "INFO port $port is available."
    }
}

try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/health" -TimeoutSec 3
    if ($health.status -eq "ok") {
        Write-Output "PASS existing backend health endpoint"
    } else {
        Write-Warning "Backend responded but did not return status=ok."
    }
} catch {
    Write-Output "INFO backend is not currently running; start it with the documented Uvicorn command."
}

Write-Output "Preflight complete. No Gemini call, graph execution, evaluator run, or response action was started."
