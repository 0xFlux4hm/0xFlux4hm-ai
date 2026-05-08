"""
agents/recon_agent.py
0xFlux4hm AI — VulnAgentRouter

Reconnaissance Agent: Discovers the attack surface of a target.
Performs host resolution, subdomain enumeration, and basic port discovery.

⚠️  THIS IS FOR EDUCATIONAL USE AND AUTHORIZED TESTING ONLY.
"""

import socket
import datetime
import os
from typing import Optional, Dict, Any, List

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from agents.base_agent import BaseAgent


# Common subdomains to probe when subfinder is not available
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "portal", "vpn", "remote", "secure", "shop", "blog", "docs",
    "support", "help", "app", "dashboard", "login", "auth", "cdn",
    "static", "assets", "images", "m", "mobile", "beta", "old",
    "backup", "db", "database", "jenkins", "gitlab", "github",
]


class ReconAgent(BaseAgent):
    """
    Reconnaissance Agent for 0xFlux4hm AI.

    Capabilities:
    - DNS resolution and IP geolocation
    - Subdomain enumeration (subfinder if available, wordlist fallback)
    - Basic open port discovery (nmap if available, Python socket fallback)
    - Attack surface summary report

    ⚠️  Only use on systems you own or have explicit written permission to test.
    """

    AGENT_NAME = "Recon Agent"
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                    3306, 3389, 5432, 6379, 8080, 8443, 8888, 9200, 27017]

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute full reconnaissance on the target.

        Args:
            target: Domain name or IP address to recon
            options: Optional dict with keys: 'use_subfinder', 'use_nmap', 'save_report'

        Returns:
            Standardized result dict with findings and output
        """
        options = options or {}
        print(f"\n[RECON] 🔍 Starting reconnaissance on: {target}")
        print("[RECON] ⚠️  This is for EDUCATIONAL and AUTHORIZED USE ONLY.\n")

        report_lines = [
            f"# Reconnaissance Report",
            f"**Target:** {target}",
            f"**Date:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Agent:** {self.AGENT_NAME} (0xFlux4hm AI)",
            "",
            "---",
            "",
        ]

        # ── Step 1: DNS Resolution ──────────────────────────────────────────
        print("[RECON] Step 1/4: DNS resolution...")
        ips = self._resolve_host(target)
        if ips:
            print(f"[RECON] ✓ Resolved to: {', '.join(ips)}")
            report_lines += [
                "## DNS Resolution",
                f"- **IPs:** {', '.join(ips)}",
                "",
            ]
            self.add_finding("Informational", "Host Resolved", 
                           f"Target {target} resolves to {', '.join(ips)}", target)
        else:
            print(f"[RECON] ✗ Could not resolve {target}")
            report_lines += ["## DNS Resolution", "- Could not resolve target.", ""]

        # ── Step 2: Subdomain Enumeration ───────────────────────────────────
        print("[RECON] Step 2/4: Subdomain enumeration...")
        use_subfinder = options.get("use_subfinder", 
                                    self.config.get("use_subfinder", True))
        subdomains = self._enumerate_subdomains(target, use_subfinder)
        
        if subdomains:
            print(f"[RECON] ✓ Found {len(subdomains)} subdomain(s)")
            report_lines += [
                "## Subdomains Discovered",
                f"*Found {len(subdomains)} subdomain(s):*",
                "",
            ]
            for sub in subdomains:
                report_lines.append(f"- `{sub}`")
            report_lines.append("")
            self.add_finding("Informational", "Subdomains Found",
                           f"Discovered {len(subdomains)} subdomains for {target}: "
                           f"{', '.join(subdomains[:5])}{'...' if len(subdomains) > 5 else ''}",
                           target)
        else:
            print("[RECON] ✗ No subdomains found")
            report_lines += ["## Subdomains", "- No subdomains discovered.", ""]

        # ── Step 3: Port Scanning ────────────────────────────────────────────
        print("[RECON] Step 3/4: Port scanning...")
        use_nmap = options.get("use_nmap", True)
        open_ports = self._scan_ports(target, ips, use_nmap)
        
        if open_ports:
            print(f"[RECON] ✓ Open ports: {', '.join(str(p) for p in open_ports)}")
            report_lines += [
                "## Open Ports",
                f"*Discovered {len(open_ports)} open port(s):*",
                "",
            ]
            for port, service in open_ports.items():
                report_lines.append(f"- **{port}/tcp** — {service}")
            report_lines.append("")
            self.add_finding("Informational", "Open Ports Discovered",
                           f"Open ports on {target}: "
                           f"{', '.join(str(p) for p in open_ports.keys())}",
                           target)
        else:
            print("[RECON] ✗ No open ports found (or scan was blocked)")
            report_lines += ["## Open Ports", "- No open ports discovered.", ""]

        # ── Step 4: Attack Surface Summary ──────────────────────────────────
        print("[RECON] Step 4/4: Building attack surface summary...")
        summary = self._build_summary(target, ips, subdomains, open_ports)
        report_lines += ["## Attack Surface Summary", summary, ""]

        # ── Compile and Save Report ──────────────────────────────────────────
        report_content = "\n".join(report_lines)
        saved_path = None
        if options.get("save_report", self.config.get("save_report", True)):
            saved_path = self._save_report(target, report_content)

        formatted_output = self.format_output(
            f"Recon Report — {target}",
            report_content,
            include_disclaimer=True
        )

        print(f"\n[RECON] ✅ Reconnaissance complete.")
        if saved_path:
            print(f"[RECON] 📄 Report saved to: {saved_path}")

        return self._result(True, formatted_output, {
            "ips": ips,
            "subdomains": subdomains,
            "open_ports": open_ports,
            "report_path": saved_path,
        })

    # ─── Private Methods ───────────────────────────────────────────────────

    def _resolve_host(self, target: str) -> List[str]:
        """Resolve hostname to IP address(es)."""
        ips = []
        try:
            # Use socket for basic resolution (always available)
            results = socket.getaddrinfo(target, None)
            ips = list(set(r[4][0] for r in results))
        except socket.gaierror as e:
            self.logger.warning(f"DNS resolution failed: {e}")
        self._log_to_db(target, f"resolve {target}", str(ips))
        return ips

    def _enumerate_subdomains(self, target: str, use_subfinder: bool) -> List[str]:
        """
        Enumerate subdomains using subfinder (if available) or wordlist probe.

        Args:
            target: Base domain (e.g., 'example.com')
            use_subfinder: Whether to try subfinder binary

        Returns:
            List of discovered subdomains
        """
        found = []

        # Try subfinder first (most comprehensive)
        if use_subfinder and self.tool_available("subfinder"):
            print("[RECON]   → Using subfinder...")
            output = self.run_command(
                ["subfinder", "-d", target, "-silent"],
                target,
                timeout=self.config.get("timeout_seconds", 60)
            )
            for line in output.strip().splitlines():
                line = line.strip()
                if line and "." in line and not line.startswith("["):
                    found.append(line)
            return found

        # Fallback: Python-based wordlist probe
        print("[RECON]   → subfinder not found, using wordlist probe...")
        for sub in COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{target}"
            try:
                socket.gethostbyname(fqdn)
                found.append(fqdn)
                print(f"[RECON]   ✓ Found: {fqdn}")
            except socket.gaierror:
                pass  # Not found, continue

        self._log_to_db(target, f"subdomain_enum {target}", str(found))
        return found

    def _scan_ports(self, target: str, ips: List[str], use_nmap: bool) -> Dict[int, str]:
        """
        Scan for open ports using nmap (if available) or Python sockets.

        Args:
            target: Target hostname
            ips: Resolved IP addresses
            use_nmap: Whether to attempt nmap

        Returns:
            Dict mapping port number to service name/guess
        """
        open_ports = {}
        scan_target = ips[0] if ips else target

        # Try nmap (requires user confirmation — it's an active scan)
        if use_nmap and self.tool_available("nmap"):
            print("[RECON]   → Using nmap for port scan...")
            output = self.run_command(
                ["nmap", "-T3", "--open", "-F", scan_target],
                target,
                timeout=self.config.get("timeout_seconds", 60),
                require_confirmation=self.config.get("require_confirmation", True),
                confirmation_message=(
                    f"nmap will actively scan {target} ({scan_target}).\n"
                    f"This sends network packets to the target."
                )
            )
            if output and "[Scan cancelled" not in output:
                open_ports = self._parse_nmap_output(output)
            return open_ports

        # Fallback: Python socket connect scan (slower but no nmap required)
        print("[RECON]   → nmap not found, using Python socket scan (slower)...")
        print(f"[RECON]   ⚠️  Scanning {len(self.COMMON_PORTS)} common ports on {scan_target}")

        for port in self.COMMON_PORTS:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.5)
                    result = s.connect_ex((scan_target, port))
                    if result == 0:
                        service = self._guess_service(port)
                        open_ports[port] = service
                        print(f"[RECON]   ✓ Open: {port}/tcp ({service})")
            except Exception:
                pass

        self._log_to_db(target, f"port_scan {target}", str(list(open_ports.keys())))
        return open_ports

    @staticmethod
    def _parse_nmap_output(output: str) -> Dict[int, str]:
        """Parse nmap text output into a port→service dict."""
        ports = {}
        for line in output.splitlines():
            # nmap lines look like: "80/tcp   open  http"
            parts = line.strip().split()
            if len(parts) >= 3 and "/tcp" in parts[0] and parts[1] == "open":
                try:
                    port = int(parts[0].split("/")[0])
                    service = parts[2] if len(parts) > 2 else "unknown"
                    ports[port] = service
                except ValueError:
                    pass
        return ports

    @staticmethod
    def _guess_service(port: int) -> str:
        """Map common port numbers to service names."""
        KNOWN = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 143: "imap",
            443: "https", 445: "smb", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 6379: "redis", 8080: "http-alt",
            8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
        }
        return KNOWN.get(port, "unknown")

    @staticmethod
    def _build_summary(target: str, ips: List[str], 
                       subdomains: List[str], open_ports: Dict) -> str:
        """Build a human-readable attack surface summary."""
        lines = []
        if ips:
            lines.append(f"- Target resolves to **{len(ips)} IP(s)**: {', '.join(ips)}")
        if subdomains:
            lines.append(f"- **{len(subdomains)} subdomain(s)** discovered, "
                        f"expanding the attack surface.")
        if open_ports:
            risky = [p for p in open_ports if p in [21, 23, 3389, 445, 6379, 27017]]
            lines.append(f"- **{len(open_ports)} open port(s)** found.")
            if risky:
                lines.append(f"- ⚠️  Potentially risky ports open: "
                            f"{', '.join(str(p) for p in risky)}")
        if not lines:
            lines.append("- No significant attack surface discovered.")
        return "\n".join(lines)

    def _save_report(self, target: str, content: str) -> str:
        """Save the reconnaissance report to a file."""
        os.makedirs("logs/reports", exist_ok=True)
        date_str = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"logs/reports/recon_{target.replace('.', '_')}_{date_str}.md"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(content)
            return filename
        except IOError as e:
            self.logger.error(f"Failed to save report: {e}")
            return ""
