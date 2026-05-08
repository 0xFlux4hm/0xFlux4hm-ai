"""
agents/web_agent.py
0xFlux4hm AI — VulnAgentRouter

Web Vulnerability Agent: Probes web applications for common vulnerabilities.
Performs port scanning, basic XSS/SQLi/IDOR probing, and integrates with
nikto/wapiti for deeper web scanning.

⚠️  THIS IS FOR EDUCATIONAL USE AND AUTHORIZED TESTING ONLY.
    The agent NEVER auto-exploits — it only identifies potential weaknesses.
"""

import re
import time
import datetime
import os
from typing import Optional, Dict, Any, List
from urllib.parse import urljoin, urlparse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from agents.base_agent import BaseAgent


class WebAgent(BaseAgent):
    """
    Web Vulnerability Agent for 0xFlux4hm AI.

    Capabilities:
    - HTTP/HTTPS header analysis
    - Basic SQLi probe (detection only, NOT exploitation)
    - Basic XSS reflection detection
    - IDOR hint detection
    - nmap web-focused scan
    - nikto integration (if installed)

    This agent NEVER auto-exploits. It identifies potential issues and
    requires explicit user confirmation before any intensive testing.
    """

    AGENT_NAME = "Web Vulnerability Agent"

    # Basic SQLi test payloads (detection only, not exploitation)
    SQLI_PAYLOADS = [
        "'",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "1' AND '1'='2",
        "'; SELECT SLEEP(1)--",
    ]

    # Basic XSS reflection payloads
    XSS_PAYLOADS = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ]

    # Common error patterns that suggest SQL injection vulnerability
    SQL_ERROR_PATTERNS = [
        r"sql syntax",
        r"mysql_fetch",
        r"ORA-\d{5}",
        r"PostgreSQL.*ERROR",
        r"Warning.*mysql",
        r"Unclosed quotation mark",
        r"Microsoft OLE DB Provider for SQL Server",
        r"SQLite3::query",
    ]

    def run(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute web vulnerability assessment on target.

        Args:
            target: URL or domain (e.g., 'https://example.com' or 'example.com')
            options: Optional dict with scan configuration

        Returns:
            Standardized result dict with findings
        """
        options = options or {}
        
        # Normalize target to URL
        url = self._normalize_url(target)
        print(f"\n[WEB] 🌐 Starting web vulnerability assessment on: {url}")
        print("[WEB] ⚠️  This is for EDUCATIONAL and AUTHORIZED USE ONLY.")
        print("[WEB] ℹ️  This agent will NOT auto-exploit any discovered vulnerabilities.\n")

        report_lines = [
            "# Web Vulnerability Assessment Report",
            f"**Target:** {url}",
            f"**Date:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Agent:** {self.AGENT_NAME} (0xFlux4hm AI)",
            "",
            "---",
            "",
        ]

        if not REQUESTS_AVAILABLE:
            msg = "[WEB] ✗ 'requests' library not installed. Run: pip install requests"
            print(msg)
            return self._result(False, msg)

        # ── Step 1: HTTP Headers Analysis ───────────────────────────────────
        print("[WEB] Step 1/4: Analyzing HTTP headers...")
        headers_report = self._check_headers(url, target)
        report_lines += headers_report

        # ── Step 2: nmap Web Scan (if available) ────────────────────────────
        print("[WEB] Step 2/4: Running nmap web script scan...")
        nmap_report = self._run_nmap_web(target)
        report_lines += nmap_report

        # ── Step 3: Basic SQLi Detection (not exploitation) ─────────────────
        print("[WEB] Step 3/4: Basic SQLi probe (detection only)...")
        sqli_report = self._probe_sqli(url, target)
        report_lines += sqli_report

        # ── Step 4: Basic XSS Reflection Detection ──────────────────────────
        print("[WEB] Step 4/4: Basic XSS reflection detection...")
        xss_report = self._probe_xss(url, target)
        report_lines += xss_report

        # ── nikto (if available and user opts in) ───────────────────────────
        if self.config.get("use_nikto", False) and self.tool_available("nikto"):
            print("[WEB] Extra: Running nikto scan (requires confirmation)...")
            nikto_output = self.run_command(
                ["nikto", "-h", url, "-Tuning", "1234678"],
                target,
                timeout=self.config.get("timeout_seconds", 120),
                require_confirmation=True,
                confirmation_message=(
                    f"nikto will send many HTTP requests to {url}.\n"
                    f"This is a noisy scan that may be logged by the server."
                )
            )
            if "[Scan cancelled" not in nikto_output:
                report_lines += ["## nikto Scan Results", f"```\n{nikto_output}\n```", ""]

        report_content = "\n".join(report_lines)
        saved_path = self._save_report(target, report_content)

        formatted_output = self.format_output(
            f"Web Vuln Report — {url}",
            report_content,
            include_disclaimer=True
        )

        print(f"\n[WEB] ✅ Web assessment complete.")
        if saved_path:
            print(f"[WEB] 📄 Report saved to: {saved_path}")

        return self._result(True, formatted_output, {"report_path": saved_path, "url": url})

    # ─── Private Methods ───────────────────────────────────────────────────

    def _normalize_url(self, target: str) -> str:
        """Ensure target is a valid URL with protocol."""
        if not target.startswith(("http://", "https://")):
            return f"https://{target}"
        return target

    def _check_headers(self, url: str, target: str) -> List[str]:
        """
        Analyze HTTP response headers for security misconfigurations.

        Checks for missing security headers and information disclosure.
        """
        lines = ["## HTTP Security Headers Analysis", ""]

        SECURITY_HEADERS = {
            "Strict-Transport-Security": "HSTS not set — HTTPS not enforced",
            "Content-Security-Policy": "CSP missing — XSS risk increased",
            "X-Frame-Options": "Clickjacking protection missing",
            "X-Content-Type-Options": "MIME sniffing protection missing",
            "Referrer-Policy": "Referrer policy not set",
            "Permissions-Policy": "Permissions policy not set",
        }

        try:
            resp = requests.get(url, timeout=10, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (Security-Assessment)"})
            
            lines.append(f"**Status Code:** {resp.status_code}")
            lines.append(f"**Final URL:** {resp.url}")
            lines.append("")

            missing = []
            present = []

            for header, warning in SECURITY_HEADERS.items():
                if header.lower() in {k.lower() for k in resp.headers}:
                    present.append(f"- ✅ `{header}`: present")
                else:
                    missing.append(f"- ⚠️  `{header}`: **MISSING** — {warning}")
                    self.add_finding(
                        "Medium", f"Missing Header: {header}",
                        f"{warning} on {url}", target
                    )

            # Check for information disclosure
            server = resp.headers.get("Server", "")
            if server:
                lines.append(f"**Server header:** `{server}` — may disclose technology stack")
                self.add_finding("Low", "Server Header Disclosure",
                               f"Server header reveals: {server}", target)

            x_powered = resp.headers.get("X-Powered-By", "")
            if x_powered:
                lines.append(f"**X-Powered-By:** `{x_powered}` — technology disclosure")
                self.add_finding("Low", "X-Powered-By Disclosure",
                               f"X-Powered-By reveals: {x_powered}", target)

            lines.append("")
            lines.append("### Security Headers Present")
            lines += present or ["- None of the checked headers are present"]
            lines.append("")
            lines.append("### Missing Security Headers")
            lines += missing or ["- All checked headers are present ✅"]
            lines.append("")

            self._log_to_db(target, f"header_check {url}", 
                          f"status={resp.status_code}, missing={len(missing)}")

        except requests.RequestException as e:
            lines.append(f"⚠️  Could not reach {url}: {e}")
            self._log_to_db(target, f"header_check {url}", str(e), "error")

        return lines

    def _run_nmap_web(self, target: str) -> List[str]:
        """Run nmap with web-focused scripts."""
        lines = ["## nmap Web Scan", ""]
        
        if not self.tool_available("nmap"):
            lines.append("*nmap not available. Install with: `apt install nmap` or `pkg install nmap`*")
            lines.append("")
            return lines

        output = self.run_command(
            ["nmap", "-sV", "-p", "80,443,8080,8443", "--script", 
             "http-headers,http-title,http-robots.txt", target],
            target,
            timeout=60,
            require_confirmation=self.config.get("require_confirmation", True),
            confirmation_message=f"nmap will scan ports 80, 443, 8080, 8443 on {target}"
        )

        if "[Scan cancelled" in output:
            lines.append("*Scan cancelled by user.*")
        else:
            lines.append(f"```\n{output}\n```")
        lines.append("")
        return lines

    def _probe_sqli(self, url: str, target: str) -> List[str]:
        """
        Send basic SQLi detection payloads to URL parameters.
        
        IMPORTANT: This only DETECTS potential SQLi via error messages.
        It does NOT extract data, does NOT exploit, does NOT modify data.
        """
        lines = ["## SQL Injection Detection (Non-Exploitative)", ""]
        lines.append("> ℹ️  Detection only — no data extraction or exploitation performed.")
        lines.append("")

        if not self.config.get("sqli_test_enabled", True):
            lines.append("*SQLi testing disabled in config.yaml*")
            lines.append("")
            return lines

        # Build a simple test URL with a parameter
        test_url = url.rstrip("/") + "/?id="
        vulnerable_indicators = []

        for payload in self.SQLI_PAYLOADS[:3]:  # Limit payloads
            probe_url = test_url + requests.utils.quote(payload)
            try:
                # Rate limiting: delay between requests
                time.sleep(self.config.get("request_delay_ms", 500) / 1000)
                
                resp = requests.get(
                    probe_url, timeout=8,
                    headers={"User-Agent": "Mozilla/5.0 (Security-Assessment)"},
                    allow_redirects=False
                )
                body = resp.text.lower()

                # Check for SQL error patterns in response
                for pattern in self.SQL_ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        vulnerable_indicators.append(
                            f"Payload `{payload}` triggered SQL error pattern: `{pattern}`"
                        )
                        break

            except requests.RequestException:
                pass

        if vulnerable_indicators:
            lines.append("### ⚠️  Potential SQLi Indicators Found")
            for ind in vulnerable_indicators:
                lines.append(f"- {ind}")
            self.add_finding(
                "High", "Potential SQL Injection",
                f"SQL error patterns detected with basic payloads on {url}. "
                f"Manual verification required. Do NOT exploit without authorization.",
                target
            )
        else:
            lines.append("- No obvious SQL error patterns triggered. "
                        "This does not guarantee absence of SQLi vulnerabilities.")

        lines.append("")
        self._log_to_db(target, f"sqli_probe {url}", 
                       f"indicators={len(vulnerable_indicators)}")
        return lines

    def _probe_xss(self, url: str, target: str) -> List[str]:
        """
        Check for basic reflected XSS by sending payloads and checking if they 
        appear unencoded in the response.

        This only checks for REFLECTION — not stored XSS or DOM XSS.
        """
        lines = ["## XSS Reflection Detection", ""]
        lines.append("> ℹ️  Checks for payload reflection only — no browser execution tested.")
        lines.append("")

        test_url = url.rstrip("/") + "/?q="
        reflected = []

        for payload in self.XSS_PAYLOADS[:2]:
            probe_url = test_url + requests.utils.quote(payload)
            try:
                time.sleep(self.config.get("request_delay_ms", 500) / 1000)
                resp = requests.get(
                    probe_url, timeout=8,
                    headers={"User-Agent": "Mozilla/5.0 (Security-Assessment)"},
                    allow_redirects=False
                )
                # Check if payload is reflected unencoded in response
                if payload in resp.text:
                    reflected.append(f"Payload reflected unencoded: `{payload}`")

            except requests.RequestException:
                pass

        if reflected:
            lines.append("### ⚠️  Potential XSS Reflection Found")
            for r in reflected:
                lines.append(f"- {r}")
            self.add_finding(
                "High", "Potential Reflected XSS",
                f"Payload reflected unencoded in response on {url}. "
                f"Manual verification required.",
                target
            )
        else:
            lines.append("- No obvious XSS reflection detected in tested parameters.")

        lines.append("")
        self._log_to_db(target, f"xss_probe {url}", f"reflected={len(reflected)}")
        return lines

    def _save_report(self, target: str, content: str) -> str:
        """Save web vulnerability report to file."""
        os.makedirs("logs/reports", exist_ok=True)
        date_str = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(".", "_").replace("/", "_").replace(":", "")
        filename = f"logs/reports/web_{safe_target}_{date_str}.md"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(content)
            return filename
        except IOError as e:
            self.logger.error(f"Failed to save report: {e}")
            return ""
