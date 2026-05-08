# 0xFlux4hm AI — VulnAgentRouter

> **An AI-powered ethical hacking agent orchestration system, powered by Claude.**

---

## ⚠️ DISCLAIMER: AUTHORIZED USE ONLY

> **This tool is strictly for educational purposes, authorized security assessments, and ethical hacking with explicit written permission from the target system owner.**
>
> Unauthorized scanning, exploitation, or testing of systems you do not own or have written permission to test is **ILLEGAL** and may violate the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, the EU Directive on Attacks Against Information Systems, and equivalent laws in your jurisdiction.
>
> **By using this tool, you accept full legal and ethical responsibility for your actions. The author(s) and contributors bear no liability.**

---

## 🧠 What is VulnAgentRouter?

**0xFlux4hm AI** is a modular, offline-ready AI agent orchestration system. It acts as a "Router AI" — it doesn't perform attacks itself, but intelligently routes your natural language requests to specialized sub-agents:

| Agent | Purpose |
|---|---|
| 🔍 **Recon Agent** | Subdomain enumeration, host discovery, attack surface mapping |
| 🌐 **Web Vuln Agent** | Port scanning, web vulnerability scanning (XSS, SQLi, IDOR) |
| 💣 **Exploit Intelligence Agent** | CVE/Exploit-DB search, patch references |
| 📄 **Report Agent** | Professional Markdown/HTML pentest reports |

The router uses **Claude AI (Anthropic)** for intelligent intent classification, with a keyword-based fallback to minimize API costs.

---

## 📁 Project Structure

```
VulnAgentRouter/
├── README.md                  # This file
├── requirements.txt           # Python dependencies
├── .env.example               # API key template
├── router.py                  # Main AI router (entry point)
├── config.yaml                # Router settings and safety flags
├── agents/
│   ├── __init__.py
│   ├── base_agent.py          # Abstract base class for all agents
│   ├── recon_agent.py         # Subdomain/host discovery agent
│   ├── web_agent.py           # Web vulnerability scanning agent
│   ├── exploit_agent.py       # Exploit/CVE intelligence agent
│   └── report_agent.py        # Report generation agent
├── tools/
│   ├── termux_setup.sh        # Automated installer for Termux (Android)
│   └── windows_setup.ps1      # Automated installer for Windows 11
└── logs/                      # Scan logs (auto-created, contains scans.db)
```

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-repo/VulnAgentRouter
cd VulnAgentRouter
```

### 2. Set Up Your API Key

Copy the example env file and add your Anthropic API key:

```bash
cp .env.example .env
```

Edit `.env`:
```
ANTHROPIC_API_KEY=your-anthropic-api-key-here
```

Or export it directly:
```bash
# Linux / Termux
export ANTHROPIC_API_KEY='your-key-here'

# Windows PowerShell
$env:ANTHROPIC_API_KEY="your-key-here"
```

### 3. Install Dependencies

#### 🐧 Termux (Android)
```bash
chmod +x tools/termux_setup.sh
bash tools/termux_setup.sh
```

#### 🪟 Windows 11
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
.\tools\windows_setup.ps1
```

#### Manual Install (Any Platform)
```bash
pip install -r requirements.txt
```

---

## 💻 Usage

### Basic Usage
```bash
# Recon mode
python router.py --target scanme.nmap.org --mode recon

# Web vulnerability scan
python router.py --target example.com --mode web

# Exploit intelligence search
python router.py --target example.com --mode exploit --cve CVE-2023-1234

# Full audit
python router.py --target scanme.nmap.org --mode full_audit

# Generate report from previous scans
python router.py --target example.com --mode report

# Natural language mode
python router.py --query "Scan for IDOR vulnerabilities on example.com"
```

### Interactive Mode
```bash
python router.py --interactive
```

### View Scan History
```bash
python router.py --history
```

---

## 🔧 Configuration

Edit `config.yaml` to customize behavior:

```yaml
safety:
  require_confirmation: true      # Prompt before aggressive scans
  max_requests_per_scan: 100      # Rate limiting
  log_all_commands: true          # Audit logging to SQLite

agents:
  recon:
    use_subfinder: true           # Requires subfinder installed
    use_amass: false
  web:
    use_nikto: true
    use_wapiti: false
    sqli_test_enabled: true
  exploit:
    use_searchsploit: true        # Requires exploitdb installed
    use_api_fallback: true        # Falls back to Exploit-DB API
```

---

## 🛠️ Optional Heavy Tools

### Termux (Android)
```bash
pkg install nmap subfinder
pip install sqlmap
```

### Windows 11 — WSL 2 + Kali Linux (Recommended for Advanced Use)

1. Enable WSL 2:
```powershell
wsl --install -d kali-linux
```

2. Inside Kali WSL:
```bash
sudo apt update && sudo apt install -y metasploit-framework nmap nikto sqlmap gobuster subfinder
```

3. Use WSL tools from router:
```bash
python router.py --target example.com --mode full_audit --use-wsl
```

---

## 📊 Example Output

```
[0xFlux4hm AI] Router initialized. Target: scanme.nmap.org
[*] Classifying intent... → Recon Agent
[RECON] Starting reconnaissance on scanme.nmap.org
[RECON] Resolved IP: 45.33.32.156
[RECON] Open ports discovered: 22, 80, 9929, 31337
[RECON] Subdomains found: 3
[RECON] Report saved to logs/recon_scanme.nmap.org_20260507.txt

⚠️  DISCLAIMER: This reconnaissance was performed for educational purposes only.
```

---

## 🔗 Ecosystem & Integrations

This framework is inspired by and compatible with:

- **[Krypteia](https://github.com/krypteia)** — MCP integration with 580+ security utilities across Linux and Termux environments
- **[claude-security-tools](https://github.com/claude-security-tools)** — Professional MCP server for Windows 11 + WSL 2
- **[Bug-Bounty-Agents](https://github.com/bug-bounty-agents)** — 43 specialized agent prompts with zero dependencies
- **[claude-bug-bounty](https://github.com/claude-bug-bounty)** — AI-native bug bounty framework where Claude acts as your co-pilot, mapping attack surfaces and guiding hunts

---

## 📜 License

MIT License. See `LICENSE` file. **Use responsibly and legally.**

---

*0xFlux4hm AI — Built for ethical hackers, by ethical hackers.*
