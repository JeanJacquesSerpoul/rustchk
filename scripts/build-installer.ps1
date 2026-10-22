<#
.SYNOPSIS
    Builds the Windows installer (NSIS) of RustChk.

.DESCRIPTION
    Builds the Leptos UI (Trunk) and the Tauri app in release mode, packages them as an NSIS
    installer, then copies it to OutDir together with its SHA-256 checksum file
    (coreutils format, readable by RustChk itself).

    Requirements: Rust (MSVC toolchain) with the wasm32-unknown-unknown target, Trunk and the
    Tauri CLI (`cargo install trunk tauri-cli`, or `npm i -g @tauri-apps/cli@2`).
    NSIS itself is downloaded by Tauri on first use.

.PARAMETER OutDir
    Where to copy the installer. Default: <repository>\release

.PARAMETER RunTests
    Run `cargo test --workspace` before packaging. Needs the UI to be built first, so the script
    builds it once in advance.

.EXAMPLE
    .\scripts\build-installer.ps1
    .\scripts\build-installer.ps1 -OutDir C:\temp\rustchk -RunTests
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'release'),
    [switch]$RunTests
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
$TargetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $Root 'target' }

function Test-Command([string]$Name) {
    [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Require-Command([string]$Name, [string]$Hint) {
    if (-not (Test-Command $Name)) { throw "'$Name' not found. $Hint" }
}

# Runs a native command and fails the script if it exits with an error.
function Invoke-Native([string]$Command, [string[]]$Arguments) {
    Write-Host "> $Command $($Arguments -join ' ')" -ForegroundColor DarkGray
    # Cargo and Tauri print progress on stderr; Windows PowerShell 5.1 turns that into terminating
    # errors under 'Stop' when output is redirected. Only the exit code matters here.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Command @Arguments } finally { $ErrorActionPreference = $previous }
    if ($LASTEXITCODE -ne 0) { throw "'$Command $($Arguments -join ' ')' failed (exit code $LASTEXITCODE)." }
}

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }

# --- Prerequisites -----------------------------------------------------------------------------

Write-Step 'Checking prerequisites'
Require-Command cargo 'Install Rust from https://rustup.rs'
Require-Command trunk 'Run: cargo install trunk'

if (Test-Command rustup) {
    $targets = & rustup target list --installed
    if ($targets -notcontains 'wasm32-unknown-unknown') {
        throw "The wasm32-unknown-unknown target is missing. Run: rustup target add wasm32-unknown-unknown"
    }
}

# `cargo tauri` (cargo install tauri-cli) or the `tauri` command (npm i -g @tauri-apps/cli).
& cargo tauri --version *> $null
if ($LASTEXITCODE -eq 0) {
    $tauriCommand = 'cargo'
    $tauriPrefix = @('tauri')
} elseif (Test-Command tauri) {
    $tauriCommand = 'tauri'
    $tauriPrefix = @()
} else {
    throw 'Tauri CLI not found. Run: cargo install tauri-cli   (or: npm i -g @tauri-apps/cli@2)'
}

# Trunk rejects NO_COLOR=1, which some terminals set.
if ($env:NO_COLOR -eq '1') { $env:NO_COLOR = 'true' }

Push-Location $Root
try {
    # --- Tests (optional) ------------------------------------------------------------------------

    if ($RunTests) {
        Write-Step 'Building the UI and running the tests'
        # The Tauri backend embeds dist/ at compile time: it must exist before `cargo test`.
        Invoke-Native trunk @('build', '--release')
        Invoke-Native cargo @('test', '--workspace')
    }

    # --- Installer ---------------------------------------------------------------------------------

    Write-Step 'Building the NSIS installer (this takes a few minutes the first time)'
    Invoke-Native $tauriCommand ($tauriPrefix + @('build', '--bundles', 'nsis'))

    $installer = Get-ChildItem -Path (Join-Path $TargetDir 'release\bundle\nsis') -Filter '*-setup.exe' |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $installer) { throw "No installer found in $TargetDir\release\bundle\nsis" }

    # --- Output ------------------------------------------------------------------------------------

    Write-Step "Copying to $OutDir"
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $dest = Join-Path $OutDir $installer.Name
    Copy-Item -Path $installer.FullName -Destination $dest -Force

    $hash = (Get-FileHash -Path $dest -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksumFile = "$dest.sha256"
    # `hash  name`, LF, no BOM: the format `sha256sum -c` and RustChk both read.
    [IO.File]::WriteAllText($checksumFile, "$hash  $($installer.Name)`n", (New-Object Text.UTF8Encoding($false)))

    Write-Host ''
    Write-Host "Installer : $dest ($([math]::Round($installer.Length / 1MB, 2)) MB)" -ForegroundColor Green
    Write-Host "SHA-256   : $hash"
    Write-Host "Checksum  : $checksumFile"
} finally {
    Pop-Location
}
