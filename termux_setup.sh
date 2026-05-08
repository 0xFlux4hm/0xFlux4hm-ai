#!/data/data/com.termux/files/usr/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# tools/termux_setup.sh
# 0xFlux4hm AI — VulnAgentRouter
# Automated dependency installer for Termux (Android)
# ─────────────────────────────────────────────────────────────────────────────
#
# Usage:
#   chmod +x tools/termux_setup.sh
#   bash tools/termux_setup.sh
#
# ⚠️  FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL USE ONLY.
# ─────────────────────────────────────────────────────────────────────────────

set -e  # Exit on error

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Banner ─────────────────────────────────────────────────────────────────────
echo -e "${GREEN}${BOLD}"
cat << 'EOF'
  ██████╗ ██╗  ██╗███████╗██╗     ██╗   ██╗██╗  ██╗
 ██╔═████╗╚██╗██╔╝██╔════╝██║     ██║   ██║╚██╗██╔╝
 ██║██╔██║ ╚███╔╝ █████╗  ██║     ██║   ██║ ╚███╔╝ 
 ████╔╝██║ ██╔██╗ ██╔══╝  ██║     ██║   ██║ ██╔██╗ 
 ╚██████╔╝██╔╝ ██╗██║     ███████╗╚██████╔╝██╔╝ ██╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝
  VulnAgentRouter — Termux Setup
  ⚠️  FOR AUTHORIZED USE AND EDUCATIONAL PURPOSES ONLY
EOF
echo -e "${RESET}"

# ── Disclaimer ─────────────────────────────────────────────────────────────────
echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${RED}${BOLD}  DISCLAIMER: AUTHORIZED USE ONLY${RESET}"
echo -e "${YELLOW}  This tool is for educational purposes and authorized testing."
echo -e "  Unauthorized scanning/testing is ILLEGAL. Use responsibly."
echo -e "${RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

# ── Check Termux environment ────────────────────────────────────────────────────
check_termux() {
    if ! command -v pkg &> /dev/null; then
        echo -e "${RED}[!] This script is designed for Termux (Android).${RESET}"
        echo -e "${YELLOW}    If you're on Linux/macOS, use pip install directly.${RESET}"
        echo -e "${YELLOW}    If you're on Windows, run tools/windows_setup.ps1 instead.${RESET}"
        exit 1
    fi
    echo -e "${GREEN}[✓] Termux environment detected.${RESET}"
}

# ── Storage permission ──────────────────────────────────────────────────────────
setup_storage() {
    echo -e "\n${CYAN}[*] Setting up Termux storage access...${RESET}"
    if command -v termux-setup-storage &> /dev/null; then
        termux-setup-storage || true
        echo -e "${GREEN}[✓] Storage setup complete.${RESET}"
    else
        echo -e "${YELLOW}[~] termux-setup-storage not available, skipping.${RESET}"
    fi
}

# ── Update package lists ────────────────────────────────────────────────────────
update_packages() {
    echo -e "\n${CYAN}[*] Updating Termux package lists...${RESET}"
    pkg update -y && pkg upgrade -y
    echo -e "${GREEN}[✓] Packages updated.${RESET}"
}

# ── Install core system packages ────────────────────────────────────────────────
install_core() {
    echo -e "\n${CYAN}[*] Installing core packages...${RESET}"
    CORE_PACKAGES="python git openssl curl wget"
    for package in $CORE_PACKAGES; do
        if pkg list-installed 2>/dev/null | grep -q "^${package}"; then
            echo -e "${GREEN}[✓] ${package} already installed.${RESET}"
        else
            echo -e "${CYAN}[*] Installing ${package}...${RESET}"
            pkg install -y "$package"
            echo -e "${GREEN}[✓] ${package} installed.${RESET}"
        fi
    done
}

# ── Install nmap ────────────────────────────────────────────────────────────────
install_nmap() {
    echo -e "\n${CYAN}[*] Installing nmap (network scanner)...${RESET}"
    if command -v nmap &> /dev/null; then
        echo -e "${GREEN}[✓] nmap already installed: $(nmap --version | head -1)${RESET}"
    else
        pkg install -y nmap
        echo -e "${GREEN}[✓] nmap installed.${RESET}"
    fi
}

# ── Install Python dependencies ─────────────────────────────────────────────────
install_python_deps() {
    echo -e "\n${CYAN}[*] Upgrading pip...${RESET}"
    python -m pip install --upgrade pip --quiet

    echo -e "${CYAN}[*] Installing Python requirements...${RESET}"
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        echo -e "${GREEN}[✓] Python dependencies installed.${RESET}"
    else
        echo -e "${YELLOW}[!] requirements.txt not found. Are you in the VulnAgentRouter directory?${RESET}"
        # Install core deps manually
        pip install anthropic python-dotenv colorama rich requests httpx pyyaml dnspython jinja2 markdown
        echo -e "${GREEN}[✓] Core Python dependencies installed manually.${RESET}"
    fi
}

# ── Optional: Install subfinder ─────────────────────────────────────────────────
install_optional_tools() {
    echo -e "\n${CYAN}[*] Optional tools installation...${RESET}"
    echo -e "${YELLOW}[?] Would you like to install optional heavy tools?${RESET}"
    echo -e "    These increase capabilities but require more storage."
    echo ""
    echo -e "    ${CYAN}1${RESET}) Install subfinder (subdomain enumeration)"
    echo -e "    ${CYAN}2${RESET}) Install sqlmap (SQL injection testing)"
    echo -e "    ${CYAN}3${RESET}) Install all optional tools"
    echo -e "    ${CYAN}4${RESET}) Skip optional tools"
    echo ""
    read -p "Choice [1-4]: " choice

    case "$choice" in
        1)
            echo -e "${CYAN}[*] Installing subfinder via pkg...${RESET}"
            pkg install -y subfinder 2>/dev/null || \
                echo -e "${YELLOW}[~] subfinder not in pkg. Install manually: https://github.com/projectdiscovery/subfinder${RESET}"
            ;;
        2)
            echo -e "${CYAN}[*] Installing sqlmap via pip...${RESET}"
            pip install sqlmap 2>/dev/null || \
                echo -e "${YELLOW}[~] sqlmap pip install failed. Try: pkg install sqlmap${RESET}"
            ;;
        3)
            pkg install -y subfinder 2>/dev/null || true
            pip install sqlmap 2>/dev/null || true
            ;;
        4|*)
            echo -e "${YELLOW}[~] Skipping optional tools.${RESET}"
            ;;
    esac
}

# ── Configure API key ───────────────────────────────────────────────────────────
setup_env() {
    echo -e "\n${CYAN}[*] Setting up environment configuration...${RESET}"
    if [ ! -f ".env" ]; then
        if [ -f ".env.example" ]; then
            cp .env.example .env
            echo -e "${GREEN}[✓] Created .env from .env.example${RESET}"
        else
            echo "ANTHROPIC_API_KEY=your-key-here" > .env
            echo -e "${GREEN}[✓] Created .env file${RESET}"
        fi
    else
        echo -e "${GREEN}[✓] .env already exists.${RESET}"
    fi

    echo ""
    echo -e "${YELLOW}[!] IMPORTANT: Set your Anthropic API key.${RESET}"
    echo -e "    Option 1 — Edit .env file:"
    echo -e "    ${CYAN}nano .env${RESET}"
    echo -e "    Set: ANTHROPIC_API_KEY=your-key-here"
    echo ""
    echo -e "    Option 2 — Export in session:"
    echo -e "    ${CYAN}export ANTHROPIC_API_KEY='your-key-here'${RESET}"
    echo ""
    echo -e "    Get your API key at: ${CYAN}https://console.anthropic.com/${RESET}"
}

# ── Create required directories ─────────────────────────────────────────────────
create_dirs() {
    echo -e "\n${CYAN}[*] Creating required directories...${RESET}"
    mkdir -p logs/reports
    echo -e "${GREEN}[✓] Directories created.${RESET}"
}

# ── Verify installation ─────────────────────────────────────────────────────────
verify_install() {
    echo -e "\n${CYAN}[*] Verifying installation...${RESET}"
    echo ""

    # Check Python
    if python --version &> /dev/null; then
        echo -e "${GREEN}[✓] Python: $(python --version)${RESET}"
    else
        echo -e "${RED}[✗] Python not found!${RESET}"
    fi

    # Check pip packages
    for pkg_name in anthropic colorama rich requests yaml dotenv; do
        if python -c "import $pkg_name" 2>/dev/null; then
            echo -e "${GREEN}[✓] Python module: $pkg_name${RESET}"
        else
            echo -e "${RED}[✗] Missing module: $pkg_name${RESET}"
        fi
    done

    # Check optional tools
    for tool in nmap subfinder sqlmap; do
        if command -v $tool &> /dev/null; then
            echo -e "${GREEN}[✓] Tool: $tool${RESET}"
        else
            echo -e "${YELLOW}[~] Optional tool not found: $tool${RESET}"
        fi
    done
}

# ── Final instructions ──────────────────────────────────────────────────────────
print_usage() {
    echo ""
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${GREEN}${BOLD}  ✅ Setup Complete! 0xFlux4hm AI is ready.${RESET}"
    echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
    echo -e "${CYAN}  Quick Start:${RESET}"
    echo -e "  ${YELLOW}# Set your API key first!${RESET}"
    echo -e "  ${CYAN}export ANTHROPIC_API_KEY='your-key-here'${RESET}"
    echo ""
    echo -e "  ${YELLOW}# Run a recon scan (safe, public test target):${RESET}"
    echo -e "  ${CYAN}python router.py --target scanme.nmap.org --mode recon${RESET}"
    echo ""
    echo -e "  ${YELLOW}# Full audit:${RESET}"
    echo -e "  ${CYAN}python router.py --target scanme.nmap.org --mode full_audit${RESET}"
    echo ""
    echo -e "  ${YELLOW}# Interactive mode:${RESET}"
    echo -e "  ${CYAN}python router.py --interactive${RESET}"
    echo ""
    echo -e "${RED}  ⚠️  Only scan systems you OWN or have WRITTEN PERMISSION to test.${RESET}"
    echo ""
}

# ── Main ────────────────────────────────────────────────────────────────────────
main() {
    check_termux
    setup_storage
    update_packages
    install_core
    install_nmap
    install_python_deps
    install_optional_tools
    setup_env
    create_dirs
    verify_install
    print_usage
}

main
