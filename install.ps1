# network-audit collector installer for Windows
# Usage: powershell -ExecutionPolicy ByPass -c "irm https://network-audit.io/install.ps1 | iex"

$ErrorActionPreference = "Stop"

$RepoUrl = if ($env:NETWORK_AUDIT_REPO) { $env:NETWORK_AUDIT_REPO } else { "https://github.com/network-audit/network-audit-collector.git" }
$InstallDir = if ($env:NETWORK_AUDIT_DIR) { $env:NETWORK_AUDIT_DIR } else { "$env:LOCALAPPDATA\network-audit" }
$BinDir = if ($env:NETWORK_AUDIT_BIN) { $env:NETWORK_AUDIT_BIN } else { "$env:LOCALAPPDATA\network-audit\bin" }

function Info($msg)  { Write-Host "==> $msg" -ForegroundColor Cyan }
function Ok($msg)    { Write-Host "==> $msg" -ForegroundColor Green }
function Warn($msg)  { Write-Host "==> $msg" -ForegroundColor Yellow }
function Err($msg)   { Write-Host "==> $msg" -ForegroundColor Red; exit 1 }

# --- Check prerequisites ---
try { git --version | Out-Null } catch { Err "git is required but not found. Install it from https://git-scm.com" }

# --- Install uv if not present ---
$uvPath = Get-Command uv -ErrorAction SilentlyContinue
if (-not $uvPath) {
    Info "Installing uv..."
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    # Refresh PATH for this session
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "User") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $uvPath = Get-Command uv -ErrorAction SilentlyContinue
    if (-not $uvPath) {
        Err "uv install succeeded but 'uv' not found in PATH. Restart your terminal and re-run."
    }
    Ok "uv installed"
} else {
    Ok "uv found at $($uvPath.Source)"
}

# --- Download or update the collector ---
if (Test-Path "$InstallDir\.git") {
    Info "Updating existing installation..."
    git -C $InstallDir pull --ff-only
    Ok "Updated to latest"
} else {
    if (Test-Path $InstallDir) {
        $backup = "${InstallDir}.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
        Warn "$InstallDir exists but is not a git repo - backing up to $backup"
        Move-Item $InstallDir $backup
    }
    Info "Cloning collector to $InstallDir..."
    git clone $RepoUrl $InstallDir
    Ok "Cloned"
}

# --- Sync dependencies (uv downloads Python if needed) ---
Info "Installing dependencies..."
Push-Location $InstallDir
uv sync --quiet
Pop-Location
Ok "Dependencies installed"

# --- Create wrapper batch file and PowerShell script ---
if (-not (Test-Path $BinDir)) { New-Item -ItemType Directory -Path $BinDir -Force | Out-Null }

# .cmd wrapper for CMD and general PATH use
$cmdWrapper = @"
@echo off
set "INSTALL_DIR=%LOCALAPPDATA%\network-audit"
if defined NETWORK_AUDIT_DIR set "INSTALL_DIR=%NETWORK_AUDIT_DIR%"
uv run --project "%INSTALL_DIR%" python "%INSTALL_DIR%\main.py" %*
"@
Set-Content -Path "$BinDir\network-audit.cmd" -Value $cmdWrapper -Encoding ASCII

# .ps1 wrapper for PowerShell
$ps1Wrapper = @'
$InstallDir = if ($env:NETWORK_AUDIT_DIR) { $env:NETWORK_AUDIT_DIR } else { "$env:LOCALAPPDATA\network-audit" }
uv run --project $InstallDir python "$InstallDir\main.py" @args
'@
Set-Content -Path "$BinDir\network-audit.ps1" -Value $ps1Wrapper -Encoding UTF8

Ok "Installed 'network-audit' to $BinDir"

# --- Add to PATH if needed ---
$userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$BinDir*") {
    Info "Adding $BinDir to your PATH..."
    [System.Environment]::SetEnvironmentVariable("Path", "$BinDir;$userPath", "User")
    $env:Path = "$BinDir;$env:Path"
    Ok "Added to PATH (restart your terminal for other sessions to pick it up)"
} else {
    Ok "$BinDir already in PATH"
}

# --- API key setup ---
Write-Host ""
Info "API Key Setup"
$configFile = "$env:USERPROFILE\.config\network-audit-collector\.env"
if (Test-Path $configFile) {
    Ok "Existing API key found in $configFile"
} else {
    Write-Host "    You need an API key from https://network-audit.io"
    Write-Host ""
    $answer = Read-Host "    Import now? [y/N]"
    if ($answer -eq "y" -or $answer -eq "Y") {
        Push-Location $InstallDir
        uv run python main.py account --import-key
        Pop-Location
    } else {
        Write-Host "    Run 'network-audit account --import-key' later to configure."
    }
}

# --- Done ---
Write-Host ""
Ok "Installation complete!"
Write-Host ""
Write-Host "    Quick start:"
Write-Host "      network-audit                          # interactive mode"
Write-Host "      network-audit linux -i hosts.json      # scan Linux hosts"
Write-Host "      network-audit status                   # check API health"
Write-Host "      network-audit account                  # check credit balance"
Write-Host "      network-audit --help                   # all options"
Write-Host ""
Write-Host "    Manage your account at https://network-audit.io"
Write-Host ""
