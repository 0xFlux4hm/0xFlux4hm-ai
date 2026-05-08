# ─────────────────────────────────────────────────────────────────────────────
# tools/windows_setup.ps1
# 0xFlux4hm AI — VulnAgentRouter
# Automated dependency installer for Windows 11
# ─────────────────────────────────────────────────────────────────────────────
#
# Usage (run as Administrator or normal user):
#   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
#   .\tools\windows_setup.ps1
#
# ⚠️  FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL USE ONLY.
# ─────────────────────────────────────────────────────────────────────────────

param(
    [switch]$SkipOptional,
    [switch]$InstallWSL,
    [switch]$NoConfirm
)

# ── Console Colors ────────────────────────────────────────────────────────────
function Write-Color($Text, $Color = "White") {
    Write-Host $Text -ForegroundColor $Color
}

function Write-Banner {
    Write-Color "`n  ██████╗ ██╗  ██╗███████╗██╗     ██╗   ██╗██╗  ██╗" "Green"
    Write-Color " ██╔═████╗╚██╗██╔╝██╔════╝██║     ██║   ██║╚██╗██╔╝" "Green"
    Write-Color " ██║██╔██║ ╚███╔╝ █████╗  ██║     ██║   ██║ ╚███╔╝ " "Green"
    Write-Color " ████╔╝██║ ██╔██╗ ██╔══╝  ██║     ██║   ██║ ██╔██╗ " "Green"
    Write-Color " ╚██████╔╝██╔╝ ██╗██║     ███████╗╚██████╔╝██╔╝ ██╗" "Green"
    Write-Color "  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝" "Green"
    Write-Color "  VulnAgentRouter — Windows 11 Setup" "Cyan"
    Write-Color "  ⚠️  FOR AUTHORIZED USE AND EDUCATIONAL PURPOSES ONLY`n" "Yellow"
}

function Write-Disclaimer {
    Write-Color ("━" * 65) "Red"
    Write-Color "  DISCLAIMER: AUTHORIZED USE ONLY" "Red"
    Write-Color "  This tool is for educational purposes and authorized testing." "Yellow"
    Write-Color "  Unauthorized scanning/testing is ILLEGAL. Use responsibly." "Yellow"
    Write-Color ("━" * 65) "Red"
    Write-Host ""

    if (-not $NoConfirm) {
        $confirm = Read-Host "Do you accept the terms? (yes/no)"
        if ($confirm -ne "yes") {
            Write-Color "Aborted." "Red"
            exit 1
        }
    }
}

# ── Check if running as Administrator ─────────────────────────────────────────
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ── Check tool availability ────────────────────────────────────────────────────
function Test-Command($cmd) {
    return [bool](Get-Command $cmd -ErrorAction SilentlyContinue)
}

# ── Detect package manager ─────────────────────────────────────────────────────
function Get-PackageManager {
    if (Test-Command "winget") {
        return "winget"
    }
    elseif (Test-Command "choco") {
        return "choco"
    }
    else {
        return $null
    }
}

# ── Install Python ─────────────────────────────────────────────────────────────
function Install-Python {
    Write-Color "`n[*] Checking Python installation..." "Cyan"
    
    if (Test-Command "python") {
        $version = python --version 2>&1
        Write-Color "[✓] Python already installed: $version" "Green"
        return $true
    }

    $pm = Get-PackageManager
    Write-Color "[*] Python not found. Installing..." "Yellow"

    if ($pm -eq "winget") {
        Write-Color "[*] Using winget to install Python..." "Cyan"
        winget install --id Python.Python.3.12 --source winget --silent --accept-package-agreements --accept-source-agreements
    }
    elseif ($pm -eq "choco") {
        Write-Color "[*] Using Chocolatey to install Python..." "Cyan"
        choco install python3 -y
    }
    else {
        Write-Color "[!] No package manager found (winget or choco)." "Red"
        Write-Color "    Please install Python manually from: https://python.org/downloads/" "Yellow"
        Write-Color "    Then re-run this script." "Yellow"
        return $false
    }

    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + 
                [System.Environment]::GetEnvironmentVariable("Path", "User")

    if (Test-Command "python") {
        Write-Color "[✓] Python installed: $(python --version)" "Green"
        return $true
    }
    else {
        Write-Color "[!] Python installation may require a shell restart." "Yellow"
        return $false
    }
}

# ── Install Git ────────────────────────────────────────────────────────────────
function Install-Git {
    Write-Color "`n[*] Checking Git installation..." "Cyan"

    if (Test-Command "git") {
        Write-Color "[✓] Git already installed: $(git --version)" "Green"
        return
    }

    $pm = Get-PackageManager
    if ($pm -eq "winget") {
        Write-Color "[*] Installing Git via winget..." "Cyan"
        winget install --id Git.Git --source winget --silent --accept-package-agreements
    }
    elseif ($pm -eq "choco") {
        Write-Color "[*] Installing Git via Chocolatey..." "Cyan"
        choco install git -y
    }
    else {
        Write-Color "[!] Please install Git from: https://git-scm.com/download/win" "Yellow"
    }

    # Refresh PATH
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + 
                [System.Environment]::GetEnvironmentVariable("Path", "User")
}

# ── Install Python Requirements ────────────────────────────────────────────────
function Install-PythonRequirements {
    Write-Color "`n[*] Upgrading pip..." "Cyan"
    python -m pip install --upgrade pip --quiet

    Write-Color "[*] Installing Python requirements..." "Cyan"
    
    $reqPath = Join-Path (Get-Location) "requirements.txt"
    if (Test-Path $reqPath) {
        python -m pip install -r requirements.txt
        Write-Color "[✓] Python requirements installed." "Green"
    }
    else {
        Write-Color "[!] requirements.txt not found. Are you in the VulnAgentRouter directory?" "Yellow"
        Write-Color "[*] Installing core packages manually..." "Cyan"
        python -m pip install anthropic python-dotenv colorama rich requests httpx pyyaml dnspython jinja2 markdown
        Write-Color "[✓] Core packages installed." "Green"
    }
}

# ── Setup .env file ────────────────────────────────────────────────────────────
function Setup-EnvFile {
    Write-Color "`n[*] Setting up environment file..." "Cyan"
    
    $envPath = ".env"
    $envExamplePath = ".env.example"
    
    if (-not (Test-Path $envPath)) {
        if (Test-Path $envExamplePath) {
            Copy-Item $envExamplePath $envPath
            Write-Color "[✓] Created .env from .env.example" "Green"
        }
        else {
            "ANTHROPIC_API_KEY=your-key-here" | Out-File $envPath -Encoding UTF8
            Write-Color "[✓] Created .env file" "Green"
        }
    }
    else {
        Write-Color "[✓] .env already exists." "Green"
    }

    Write-Color "`n[!] IMPORTANT: Set your Anthropic API key in .env" "Yellow"
    Write-Color "    Edit .env and set: ANTHROPIC_API_KEY=your-key-here" "Cyan"
    Write-Color "    Or in PowerShell: `$env:ANTHROPIC_API_KEY='your-key'" "Cyan"
    Write-Color "    Get your key at: https://console.anthropic.com/" "Cyan"
}

# ── Create required directories ────────────────────────────────────────────────
function Create-Directories {
    Write-Color "`n[*] Creating required directories..." "Cyan"
    $dirs = @("logs", "logs\reports")
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Color "[✓] Created: $dir" "Green"
        }
        else {
            Write-Color "[✓] Exists: $dir" "Green"
        }
    }
}

# ── Optional: Install WSL 2 + Kali Linux ──────────────────────────────────────
function Install-WSL {
    Write-Color "`n[WSL] Setting up WSL 2 + Kali Linux for advanced tools..." "Magenta"
    
    if (-not (Test-Admin)) {
        Write-Color "[!] WSL installation requires Administrator privileges." "Red"
        Write-Color "    Please run PowerShell as Administrator and use: .\tools\windows_setup.ps1 -InstallWSL" "Yellow"
        return
    }

    Write-Color "[*] Enabling WSL feature..." "Cyan"
    try {
        wsl --install -d kali-linux
        Write-Color "[✓] WSL installation initiated. A reboot may be required." "Green"
        Write-Color "[*] After reboot, open Kali WSL and run:" "Yellow"
        Write-Color "    sudo apt update && sudo apt install -y nmap nikto sqlmap subfinder metasploit-framework" "Cyan"
    }
    catch {
        Write-Color "[!] WSL installation failed: $_" "Red"
        Write-Color "    Enable WSL manually: Settings → Windows Features → Windows Subsystem for Linux" "Yellow"
    }
}

# ── Install nmap for Windows ───────────────────────────────────────────────────
function Install-Nmap {
    Write-Color "`n[*] Checking nmap..." "Cyan"
    
    if (Test-Command "nmap") {
        Write-Color "[✓] nmap already installed." "Green"
        return
    }

    $pm = Get-PackageManager
    if ($pm -eq "winget") {
        Write-Color "[*] Installing nmap via winget..." "Cyan"
        winget install --id Insecure.Nmap --source winget --silent --accept-package-agreements
        Write-Color "[✓] nmap installed." "Green"
    }
    elseif ($pm -eq "choco") {
        Write-Color "[*] Installing nmap via Chocolatey..." "Cyan"
        choco install nmap -y
    }
    else {
        Write-Color "[~] Install nmap manually from: https://nmap.org/download.html" "Yellow"
    }
}

# ── Verify installation ────────────────────────────────────────────────────────
function Verify-Installation {
    Write-Color "`n[*] Verifying installation..." "Cyan"
    Write-Host ""

    # Python
    if (Test-Command "python") {
        Write-Color "[✓] Python: $(python --version)" "Green"
    }
    else {
        Write-Color "[✗] Python: NOT FOUND" "Red"
    }

    # pip modules
    $modules = @("anthropic", "colorama", "rich", "requests", "yaml", "dotenv")
    foreach ($mod in $modules) {
        $result = python -c "import $mod; print('ok')" 2>&1
        if ($result -eq "ok") {
            Write-Color "[✓] Python module: $mod" "Green"
        }
        else {
            Write-Color "[✗] Missing module: $mod" "Red"
        }
    }

    # Tools
    $tools = @("nmap", "git")
    foreach ($tool in $tools) {
        if (Test-Command $tool) {
            Write-Color "[✓] Tool: $tool" "Green"
        }
        else {
            Write-Color "[~] Optional tool not found: $tool" "Yellow"
        }
    }
}

# ── Print usage instructions ───────────────────────────────────────────────────
function Print-Usage {
    Write-Host ""
    Write-Color ("━" * 65) "Green"
    Write-Color "  ✅ Setup Complete! 0xFlux4hm AI is ready." "Green"
    Write-Color ("━" * 65) "Green"
    Write-Host ""
    Write-Color "  Quick Start:" "Cyan"
    Write-Host ""
    Write-Color "  # Set your API key:" "Yellow"
    Write-Color "  `$env:ANTHROPIC_API_KEY = 'your-key-here'" "Cyan"
    Write-Host ""
    Write-Color "  # Or edit .env file:" "Yellow"
    Write-Color "  notepad .env" "Cyan"
    Write-Host ""
    Write-Color "  # Run a recon scan (safe, public test target):" "Yellow"
    Write-Color "  python router.py --target scanme.nmap.org --mode recon" "Cyan"
    Write-Host ""
    Write-Color "  # Full audit:" "Yellow"
    Write-Color "  python router.py --target scanme.nmap.org --mode full_audit" "Cyan"
    Write-Host ""
    Write-Color "  # Interactive mode:" "Yellow"
    Write-Color "  python router.py --interactive" "Cyan"
    Write-Host ""
    Write-Color "  # For advanced tools (Metasploit, John, etc.) — Use WSL 2 + Kali:" "Yellow"
    Write-Color "  .\tools\windows_setup.ps1 -InstallWSL" "Cyan"
    Write-Host ""
    Write-Color "  ⚠️  Only scan systems you OWN or have WRITTEN PERMISSION to test." "Red"
    Write-Host ""
}

# ── Main ───────────────────────────────────────────────────────────────────────
function Main {
    Write-Banner
    Write-Disclaimer

    $pythonOk = Install-Python
    if (-not $pythonOk) {
        Write-Color "[!] Python installation failed. Please install manually." "Red"
        exit 1
    }

    Install-Git
    Install-Nmap
    Install-PythonRequirements
    Setup-EnvFile
    Create-Directories

    if ($InstallWSL) {
        Install-WSL
    }
    elseif (-not $SkipOptional) {
        Write-Color "`n[?] Would you like to install WSL 2 + Kali Linux for advanced tools?" "Yellow"
        Write-Color "    (Requires Administrator privileges and a reboot)" "Yellow"
        $wslChoice = Read-Host "Install WSL 2 + Kali? (yes/no)"
        if ($wslChoice -eq "yes") {
            Install-WSL
        }
    }

    Verify-Installation
    Print-Usage
}

Main
