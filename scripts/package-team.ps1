[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DestinationPath
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$destination = if (
    [System.IO.Path]::IsPathRooted($DestinationPath)
) {
    [System.IO.Path]::GetFullPath($DestinationPath)
} else {
    [System.IO.Path]::GetFullPath(
        [System.IO.Path]::Combine(
            (Get-Location).Path,
            $DestinationPath
        )
    )
}
$staging = Join-Path (Split-Path -Parent $root) ".aegis-team-package"

if (Test-Path -LiteralPath $staging) {
    throw "Refusing to use existing staging path: $staging"
}

New-Item -ItemType Directory -Path $staging | Out-Null
try {
    $arguments = @(
        $root,
        $staging,
        "/E",
        "/XD",
        ".git",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "dist",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".vite",
        "runs.json",
        "runs.json.tmp",
        "/XF",
        ".env",
        "*.pyc",
        "*.log",
        "/NFL",
        "/NDL",
        "/NJH",
        "/NJS",
        "/NP"
    )
    & robocopy @arguments
    if ($LASTEXITCODE -gt 7) {
        throw "robocopy failed with exit code $LASTEXITCODE."
    }

    Get-ChildItem -LiteralPath $staging -Recurse -Force -File |
        Where-Object {
            $_.Name -match '^\.env\.(?!example$)'
        } |
        Remove-Item -Force

    $destinationDirectory = Split-Path -Parent $destination
    if (-not (Test-Path -LiteralPath $destinationDirectory)) {
        New-Item -ItemType Directory -Path $destinationDirectory | Out-Null
    }
    if (Test-Path -LiteralPath $destination) {
        throw "Refusing to overwrite existing destination: $destination"
    }
    Compress-Archive -Path (Join-Path $staging "*") -DestinationPath $destination
    Write-Output "Created team ZIP: $destination"
} finally {
    Remove-Item -LiteralPath $staging -Recurse -Force
}
