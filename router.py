#!/usr/bin/env python3
"""
router.py
0xFlux4hm AI — VulnAgentRouter

Main AI Router Script. The "brain" of the system.
Accepts natural language or structured input, classifies intent using
keyword matching (fast, free) or Claude AI (intelligent), then routes
to the appropriate specialist sub-agent.

Usage:
  python router.py --target scanme.nmap.org --mode recon
  python router.py --target example.com --mode full_audit
  python router.py --query "Scan for XSS on example.com"
  python router.py --interactive
  python router.py --history

⚠️  FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY.
"""

import os
import sys
import argparse
import json
import sqlite3
import datetime
import logging
import re
import yaml
from typing import Optional, Dict, Any

# ── Dependency imports with friendly error messages ───────────────────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("[!] python-dotenv not installed. Run: pip install python-dotenv")
    sys.exit(1)

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""
    class Back:
        RED = ""

try:
    import anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

# ── Local imports ──────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from agents.recon_agent import ReconAgent
from agents.web_agent import WebAgent
from agents.exploit_agent import ExploitAgent
from agents.report_agent import ReportAgent

# ── Banner ─────────────────────────────────────────────────────────────────────
BANNER = r"""
  ██████╗ ██╗  ██╗███████╗██╗     ██╗   ██╗██╗  ██╗
 ██╔═████╗╚██╗██╔╝██╔════╝██║     ██║   ██║╚██╗██╔╝
 ██║██╔██║ ╚███╔╝ █████╗  ██║     ██║   ██║ ╚███╔╝ 
 ████╔╝██║ ██╔██╗ ██╔══╝  ██║     ██║   ██║ ██╔██╗ 
 ╚██████╔╝██╔╝ ██╗██║     ███████╗╚██████╔╝██╔╝ ██╗
  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝
  ██╗  ██╗███╗   ███╗     █████╗ ██╗
  ██║  ██║████╗ ████║    ██╔══██╗██║
  ███████║██╔████╔██║    ███████║██║
  ╚════██║██║╚██╔╝██║    ██╔══██║██║
       ██║██║ ╚═╝ ██║    ██║  ██║██║
       ╚═╝╚═╝     ╚═╝    ╚═╝  ╚═╝╚═╝

  VulnAgentRouter v1.0 — AI-Powered Ethical Hacking Assistant
  ⚠️  FOR AUTHORIZED SECURITY TESTING AND EDUCATIONAL USE ONLY
"""

# ── Routing Keywords (fast, no API cost) ──────────────────────────────────────
ROUTING_KEYWORDS = {
    "recon": [
        "recon", "reconnaissance", "subdomain", "discovery", "enumerate",
        "enumerate", "dns", "subdomains", "attack surface", "fingerprint",
        "nslookup", "dig", "host discovery", "amass", "subfinder"
    ],
    "web": [
        "web", "xss", "sqli", "sql injection", "idor", "csrf", "lfi", "rfi",
        "ssrf", "injection", "vulnerability", "vuln", "http", "https",
        "nikto", "wapiti", "burp", "scan web", "web app", "application"
    ],
    "exploit": [
        "exploit", "cve", "searchsploit", "metasploit", "payload", "shellcode",
        "rce", "remote code", "privilege escalation", "privesc", "exploit-db",
        "patch", "vulnerability database", "known vuln", "poc"
    ],
    "report": [
        "report", "generate report", "summary", "findings", "documentation",
        "pdf", "markdown", "executive", "output", "results", "write up",
        "pentest report", "assessment report"
    ],
    "full_audit": [
        "full", "audit", "complete", "all", "full scan", "full assessment",
        "everything", "comprehensive", "full_audit"
    ]
}


class VulnAgentRouter:
    """
    The central AI router for 0xFlux4hm AI.

    Responsibilities:
    1. Accept user input (structured args or natural language)
    2. Classify intent via keyword matching or Claude AI API
    3. Route to the correct sub-agent
    4. Persist session context to avoid repeated API calls
    5. Aggregate results and trigger report generation
    """

    def __init__(self, config_path: str = "config.yaml", db_path: str = "logs/scans.db"):
        self.config = self._load_config(config_path)
        self.db_path = db_path
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        self.session_context = []  # Persistent session context
        self.all_findings = []     # Aggregated findings across agents
        self.agent_outputs = {}    # Raw outputs from each agent

        # Setup logging
        self._setup_logging()

        # Validate API key (optional — keyword routing works without it)
        if not self.api_key:
            self.logger.warning(
                "ANTHROPIC_API_KEY not set. Using keyword-based routing only. "
                "Set the key in .env for intelligent routing."
            )

        # Init database
        os.makedirs("logs", exist_ok=True)
        os.makedirs("logs/reports", exist_ok=True)
        self._init_db()

    # ─── Configuration ─────────────────────────────────────────────────────

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load YAML configuration file."""
        defaults = {
            "router": {"model": "claude-sonnet-4-20250514", "keyword_fallback": True},
            "safety": {"require_confirmation": True, "log_all_commands": True},
            "agents": {
                "recon": {"use_subfinder": True, "timeout_seconds": 60, "save_report": True},
                "web": {"sqli_test_enabled": True, "request_delay_ms": 500, "timeout_seconds": 120},
                "exploit": {"use_searchsploit": True, "use_api_fallback": True, "max_results": 10},
                "report": {"output_format": "markdown"},
            },
            "logging": {"db_path": "logs/scans.db", "log_level": "INFO"},
        }
        try:
            with open(config_path, "r") as f:
                loaded = yaml.safe_load(f)
                # Deep merge with defaults
                for key, val in loaded.items():
                    if isinstance(val, dict) and key in defaults:
                        defaults[key].update(val)
                    else:
                        defaults[key] = val
                return defaults
        except FileNotFoundError:
            return defaults
        except Exception as e:
            print(f"[!] Config load error: {e}. Using defaults.")
            return defaults

    def _setup_logging(self):
        """Configure the logging system."""
        log_level = self.config.get("logging", {}).get("log_level", "INFO")
        logging.basicConfig(
            level=getattr(logging, log_level, logging.INFO),
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(
                    self.config.get("logging", {}).get("log_file", "logs/router.log"),
                    mode="a", encoding="utf-8"
                ) if self.config.get("logging", {}).get("log_to_file", True) else logging.NullHandler()
            ]
        )
        self.logger = logging.getLogger("VulnAgentRouter")

    def _init_db(self):
        """Initialize the SQLite audit log database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS router_log (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp   TEXT NOT NULL,
                        target      TEXT,
                        mode        TEXT,
                        query       TEXT,
                        routed_to   TEXT,
                        status      TEXT DEFAULT 'success'
                    )
                """)
                conn.commit()
        except sqlite3.Error as e:
            self.logger.error(f"DB init error: {e}")

    def _log_route(self, target: str, mode: str, query: str, routed_to: str, status: str = "success"):
        """Log routing decision to SQLite."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO router_log (timestamp, target, mode, query, routed_to, status) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (datetime.datetime.utcnow().isoformat(), target, mode, query, routed_to, status)
                )
                conn.commit()
        except sqlite3.Error:
            pass

    # ─── Intent Classification ─────────────────────────────────────────────

    def classify_intent(self, query: str, mode: Optional[str] = None) -> str:
        """
        Classify user intent to determine which agent to route to.

        Strategy:
        1. If --mode is specified, use it directly (explicit routing)
        2. Try keyword matching (fast, no API cost)
        3. Fall back to Claude API for complex/ambiguous queries

        Args:
            query: Natural language query or empty string
            mode: Explicit mode from --mode flag

        Returns:
            Route string: 'recon', 'web', 'exploit', 'report', or 'full_audit'
        """
        # Explicit mode always wins
        if mode and mode.lower() in ROUTING_KEYWORDS:
            self._print(f"[ROUTER] Direct mode: {mode.upper()}", Fore.CYAN)
            return mode.lower()

        if not query:
            return "recon"  # Default

        # Keyword-based classification (fast path)
        query_lower = query.lower()
        scores = {route: 0 for route in ROUTING_KEYWORDS}
        for route, keywords in ROUTING_KEYWORDS.items():
            for kw in keywords:
                if kw in query_lower:
                    scores[route] += 1

        best_route = max(scores, key=scores.get)
        best_score = scores[best_route]

        if best_score > 0:
            self._print(f"[ROUTER] Keyword match → {best_route.upper()} "
                       f"(score: {best_score})", Fore.CYAN)
            return best_route

        # Claude AI fallback for ambiguous queries
        if ANTHROPIC_AVAILABLE and self.api_key:
            return self._claude_classify(query)

        self._print("[ROUTER] Could not classify intent. Defaulting to 'recon'.", Fore.YELLOW)
        return "recon"

    def _claude_classify(self, query: str) -> str:
        """Use Claude API to classify the user's intent."""
        self._print("[ROUTER] Using Claude AI for intent classification...", Fore.MAGENTA)

        # Build classification prompt
        system_prompt = (
            "You are a routing classifier for an ethical hacking AI system. "
            "Classify the user's security testing intent into EXACTLY ONE of these categories: "
            "recon, web, exploit, report, full_audit. "
            "Respond with ONLY the category name, nothing else. "
            "recon = subdomain/host discovery, web = web vulnerability scanning, "
            "exploit = CVE/exploit database search, report = generate a report, "
            "full_audit = comprehensive assessment."
        )

        # Add to session context (persist across calls)
        self.session_context.append({"role": "user", "content": query})

        try:
            client = anthropic.Anthropic(api_key=self.api_key)
            response = client.messages.create(
                model=self.config["router"].get("model", "claude-sonnet-4-20250514"),
                max_tokens=20,
                system=system_prompt,
                messages=[{"role": "user", "content": f"Classify this query: {query}"}]
            )
            route = response.content[0].text.strip().lower()
            if route in ROUTING_KEYWORDS:
                self._print(f"[ROUTER] Claude classified → {route.upper()}", Fore.MAGENTA)
                return route
        except Exception as e:
            self.logger.warning(f"Claude API classification failed: {e}")

        return "recon"

    # ─── Agent Execution ───────────────────────────────────────────────────

    def _get_agent_config(self, agent_name: str) -> Dict[str, Any]:
        """Get agent-specific config merged with safety settings."""
        agent_cfg = self.config.get("agents", {}).get(agent_name, {})
        safety_cfg = self.config.get("safety", {})
        # Merge: safety settings apply to all agents
        return {**agent_cfg, **safety_cfg}

    def route(self, target: str, mode: str = "recon",
              query: str = "", options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Main routing method. Classifies intent and dispatches to the correct agent.

        Args:
            target: Target domain/IP
            mode: Explicit mode (or '' for auto-classify)
            query: Natural language query
            options: Additional options passed to agent

        Returns:
            Agent result dict
        """
        options = options or {}

        # Classify intent
        route = self.classify_intent(query or mode, mode)

        self._print(f"\n[ROUTER] ⚡ Routing to: {route.upper().replace('_', ' ')}", 
                   Fore.GREEN + Style.BRIGHT)
        self._log_route(target, mode, query, route)

        result = {}

        if route == "recon":
            result = self._run_recon(target, options)

        elif route == "web":
            result = self._run_web(target, options)

        elif route == "exploit":
            result = self._run_exploit(target, options)

        elif route == "report":
            result = self._run_report(target, options)

        elif route == "full_audit":
            result = self._run_full_audit(target, options)

        else:
            self._print(f"[ROUTER] Unknown route: {route}", Fore.RED)
            result = {"success": False, "output": f"Unknown route: {route}"}

        return result

    def _run_recon(self, target: str, options: Dict) -> Dict:
        """Execute the Recon Agent."""
        agent = ReconAgent(self._get_agent_config("recon"), self.db_path)
        result = agent.run(target, options)
        self.all_findings.extend(result.get("findings", []))
        self.agent_outputs["Recon Agent"] = result.get("output", "")
        return result

    def _run_web(self, target: str, options: Dict) -> Dict:
        """Execute the Web Vulnerability Agent."""
        agent = WebAgent(self._get_agent_config("web"), self.db_path)
        result = agent.run(target, options)
        self.all_findings.extend(result.get("findings", []))
        self.agent_outputs["Web Agent"] = result.get("output", "")
        return result

    def _run_exploit(self, target: str, options: Dict) -> Dict:
        """Execute the Exploit Intelligence Agent."""
        agent = ExploitAgent(self._get_agent_config("exploit"), self.db_path)
        result = agent.run(target, options)
        self.all_findings.extend(result.get("findings", []))
        self.agent_outputs["Exploit Agent"] = result.get("output", "")
        return result

    def _run_report(self, target: str, options: Dict) -> Dict:
        """Execute the Report Agent with accumulated findings."""
        agent = ReportAgent(self._get_agent_config("report"), self.db_path)
        # Pass all accumulated findings from this session
        report_options = {
            **options,
            "findings": self.all_findings,
            "agent_outputs": self.agent_outputs,
            "format": options.get("format",
                                  self.config.get("agents", {}).get("report", {}).get(
                                      "output_format", "both"))
        }
        result = agent.run(target, report_options)
        return result

    def _run_full_audit(self, target: str, options: Dict) -> Dict:
        """Run all agents in sequence: Recon → Web → Exploit → Report."""
        self._print("\n[ROUTER] 🔥 FULL AUDIT MODE — Running all agents in sequence\n",
                   Fore.YELLOW + Style.BRIGHT)

        results = {}

        # 1. Recon
        self._print("[ROUTER] Phase 1/4: Reconnaissance", Fore.CYAN)
        results["recon"] = self._run_recon(target, options)

        # 2. Web
        self._print("\n[ROUTER] Phase 2/4: Web Vulnerability Assessment", Fore.CYAN)
        results["web"] = self._run_web(target, options)

        # 3. Exploit Intelligence
        self._print("\n[ROUTER] Phase 3/4: Exploit Intelligence", Fore.CYAN)
        results["exploit"] = self._run_exploit(target, options)

        # 4. Report (auto-generates after all agents complete)
        self._print("\n[ROUTER] Phase 4/4: Generating Report", Fore.CYAN)
        results["report"] = self._run_report(target, options)

        self._print("\n[ROUTER] ✅ Full audit complete!", Fore.GREEN + Style.BRIGHT)
        return results

    # ─── Interactive Mode ──────────────────────────────────────────────────

    def interactive_mode(self):
        """Run the router in interactive REPL mode."""
        self._print_banner()
        self._print(
            "\n[0xFlux4hm AI] Interactive mode. Type 'help' for commands, 'exit' to quit.\n",
            Fore.CYAN
        )

        current_target = None

        while True:
            try:
                prompt = f"\n{Fore.GREEN}0xFlux4hm{Fore.WHITE}@{Fore.CYAN}{current_target or 'no-target'}{Style.RESET_ALL}> "
                user_input = input(prompt).strip()

                if not user_input:
                    continue

                if user_input.lower() in ("exit", "quit", "q"):
                    self._print("\n[0xFlux4hm AI] Session ended. Stay ethical. 🔒", Fore.YELLOW)
                    break

                elif user_input.lower() == "help":
                    self._print_help()

                elif user_input.lower().startswith("target "):
                    current_target = user_input.split(" ", 1)[1].strip()
                    self._print(f"[*] Target set: {current_target}", Fore.GREEN)

                elif user_input.lower() == "history":
                    self._show_history()

                elif user_input.lower() == "findings":
                    self._show_findings()

                elif user_input.lower().startswith("report"):
                    if not current_target:
                        self._print("[!] Set a target first: target <domain>", Fore.RED)
                    else:
                        self.route(current_target, mode="report")

                elif current_target:
                    # Natural language routing
                    self.route(current_target, query=user_input)

                else:
                    self._print("[!] Set a target first: target <domain>", Fore.RED)

            except KeyboardInterrupt:
                self._print("\n\n[0xFlux4hm AI] Interrupted. Type 'exit' to quit.", Fore.YELLOW)
            except EOFError:
                break

    # ─── History & Reporting ───────────────────────────────────────────────

    def show_history(self):
        """Display scan history from SQLite database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute(
                    "SELECT timestamp, target, mode, routed_to, status "
                    "FROM router_log ORDER BY id DESC LIMIT 20"
                ).fetchall()

            if not rows:
                self._print("No scan history found.", Fore.YELLOW)
                return

            self._print("\n📋 Recent Scan History (last 20):", Fore.CYAN + Style.BRIGHT)
            self._print("─" * 80, Fore.CYAN)
            print(f"{'Timestamp':<22} {'Target':<25} {'Mode':<12} {'Agent':<15} {'Status'}")
            self._print("─" * 80, Fore.CYAN)
            for row in rows:
                ts, target, mode, routed_to, status = row
                status_color = Fore.GREEN if status == "success" else Fore.RED
                print(f"{ts[:19]:<22} {(target or ''):<25} {(mode or ''):<12} "
                      f"{(routed_to or ''):<15} {status_color}{status}")

        except sqlite3.Error as e:
            self._print(f"Database error: {e}", Fore.RED)

    def _show_findings(self):
        """Display accumulated findings for current session."""
        if not self.all_findings:
            self._print("No findings in current session.", Fore.YELLOW)
            return

        self._print(f"\n🔍 Session Findings ({len(self.all_findings)} total):", 
                   Fore.CYAN + Style.BRIGHT)
        self._print("─" * 60, Fore.CYAN)
        for i, f in enumerate(self.all_findings, 1):
            sev = f.get("severity", "Info")
            sev_color = {
                "Critical": Fore.RED, "High": Fore.RED,
                "Medium": Fore.YELLOW, "Low": Fore.GREEN,
                "Informational": Fore.BLUE
            }.get(sev, Fore.WHITE)
            print(f"  {i}. [{sev_color}{sev}{Style.RESET_ALL}] {f.get('title','')}")

    # ─── Display Helpers ───────────────────────────────────────────────────

    def _print_banner(self):
        """Print the 0xFlux4hm AI banner."""
        if COLORS:
            print(Fore.GREEN + Style.BRIGHT + BANNER + Style.RESET_ALL)
        else:
            print(BANNER)

    def _print_help(self):
        """Print interactive mode help."""
        help_text = f"""
{Fore.CYAN + Style.BRIGHT}0xFlux4hm AI — Command Reference{Style.RESET_ALL}
{"─" * 40}
{Fore.GREEN}target <domain>{Fore.WHITE}     Set the current target
{Fore.GREEN}recon{Fore.WHITE}               Run reconnaissance
{Fore.GREEN}web{Fore.WHITE}                 Run web vulnerability scan
{Fore.GREEN}exploit{Fore.WHITE}             Search exploit/CVE database
{Fore.GREEN}report{Fore.WHITE}              Generate session report
{Fore.GREEN}findings{Fore.WHITE}            Show current session findings
{Fore.GREEN}history{Fore.WHITE}             Show scan history
{Fore.GREEN}exit / quit{Fore.WHITE}         Exit the router

{Fore.YELLOW}Or type any natural language query, e.g.:{Fore.WHITE}
  "Scan for IDOR vulnerabilities"
  "Look up CVE-2021-44228"
  "Check subdomains and open ports"
{"─" * 40}
{Fore.RED}⚠️  Only scan systems you own or have written permission to test.{Fore.WHITE}
"""
        print(help_text)

    @staticmethod
    def _print(msg: str, color: str = ""):
        """Print with optional color."""
        if COLORS and color:
            print(color + msg + Style.RESET_ALL)
        else:
            # Strip ANSI escapes for non-color mode
            print(re.sub(r'\x1b\[[0-9;]*m', '', msg))

    def _show_history(self):
        """Alias for show_history in interactive mode."""
        self.show_history()


# ── CLI Entry Point ────────────────────────────────────────────────────────────

def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="0xFlux4hm AI — VulnAgentRouter",
        description="AI-powered ethical hacking agent router. For authorized use only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python router.py --target scanme.nmap.org --mode recon
  python router.py --target example.com --mode web
  python router.py --target example.com --mode exploit --cve CVE-2021-44228
  python router.py --target example.com --mode full_audit
  python router.py --query "Scan for XSS on example.com"
  python router.py --interactive
  python router.py --history

⚠️  AUTHORIZED USE ONLY. See README.md for full disclaimer.
        """
    )
    parser.add_argument("--target", "-t", help="Target domain or IP address")
    parser.add_argument(
        "--mode", "-m",
        choices=["recon", "web", "exploit", "report", "full_audit"],
        help="Operation mode"
    )
    parser.add_argument("--query", "-q", help="Natural language query (auto-routes)")
    parser.add_argument("--cve", help="CVE ID for exploit agent (e.g., CVE-2021-44228)")
    parser.add_argument("--interactive", "-i", action="store_true",
                       help="Launch interactive REPL mode")
    parser.add_argument("--history", action="store_true",
                       help="Show scan history from database")
    parser.add_argument("--config", default="config.yaml",
                       help="Path to config.yaml (default: config.yaml)")
    parser.add_argument("--format", choices=["markdown", "html", "both"],
                       default="both", help="Report output format")
    parser.add_argument("--no-confirm", action="store_true",
                       help="Skip confirmation prompts (use with caution)")
    parser.add_argument("--version", "-v", action="version",
                       version="0xFlux4hm AI VulnAgentRouter v1.0")
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_args()

    # Initialize router
    router = VulnAgentRouter(config_path=args.config)

    # Override safety confirmation if --no-confirm passed
    if args.no_confirm:
        router.config.setdefault("safety", {})["require_confirmation"] = False
        router._print(
            "[!] WARNING: Confirmation prompts disabled. Ensure you have authorization!",
            Fore.RED + Style.BRIGHT
        )

    # Print banner
    router._print_banner()

    # ── Mode dispatch ──────────────────────────────────────────────────────
    if args.interactive:
        router.interactive_mode()

    elif args.history:
        router.show_history()

    elif args.query:
        # Natural language mode — extract target from query if not provided
        target = args.target or _extract_target_from_query(args.query)
        if not target:
            router._print(
                "[!] Could not determine target from query. "
                "Use --target to specify explicitly.",
                Fore.RED
            )
            sys.exit(1)

        options = {}
        if args.cve:
            options["cve"] = args.cve
        options["format"] = args.format

        router.route(target, query=args.query, options=options)

    elif args.target:
        mode = args.mode or "recon"
        options = {}
        if args.cve:
            options["cve"] = args.cve
        options["format"] = args.format

        router.route(args.target, mode=mode, options=options)

    else:
        router._print(
            "[!] No target specified. Use --target, --query, or --interactive.\n"
            "    Run: python router.py --help",
            Fore.YELLOW
        )
        router._print_help()


def _extract_target_from_query(query: str) -> Optional[str]:
    """
    Attempt to extract a domain/IP from a natural language query.
    Simple heuristic: looks for domain-like patterns.
    """
    # Match domain names (e.g., example.com, test.example.org)
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    matches = re.findall(domain_pattern, query)
    if matches:
        return matches[0]
    # Match IP addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_matches = re.findall(ip_pattern, query)
    if ip_matches:
        return ip_matches[0]
    return None


if __name__ == "__main__":
    main()
