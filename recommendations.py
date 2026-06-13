"""
recommendations.py — Phase 5: generate an HTML report from the risk findings.

Takes the scored findings from Phase 4, attaches concrete remediation steps
to each one, and writes a self-contained HTML file to the reports/ directory.
The HTML report is the deliverable — something you can open in a browser and
hand to a client or read through yourself without needing any extra tools.

Usage:
    from analyzer.recommendations import ReportGenerator

    rg = ReportGenerator(target="192.168.56.101")
    rg.generate(risks)
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# Concrete remediation steps per service.
# Each entry is a specific action, not a vague suggestion like "improve security".
REMEDIATION_MAP: Dict[str, List[str]] = {
    "telnet": [
        "Disable the Telnet service immediately — it has no legitimate use in modern environments.",
        "Replace with SSH for all remote access requirements.",
        "Block port 23 at the firewall for all external and internal traffic.",
        "Audit user accounts that may have been using Telnet — rotate all passwords.",
    ],
    "ftp": [
        "Disable plain FTP and replace with SFTP (SSH File Transfer Protocol) or FTPS.",
        "If FTP must remain, enforce TLS encryption and disable anonymous access.",
        "Restrict FTP access to specific IP ranges using firewall rules.",
        "Review FTP logs for any unauthorised access or data exfiltration.",
    ],
    "ssh": [
        "Disable SSH password authentication — use SSH key pairs only.",
        "Ensure the SSH version is current (OpenSSH 8.x or higher).",
        "Change the default port (22) to reduce automated scanning noise.",
        "Implement fail2ban or equivalent to block brute-force attempts.",
        "Restrict SSH access to specific IP addresses where possible.",
    ],
    "http": [
        "Redirect all HTTP traffic to HTTPS using a 301 permanent redirect.",
        "Implement HTTP Strict Transport Security (HSTS) header.",
        "Review server response headers — remove version information (Server: header).",
        "Check for directory listing being enabled and disable it.",
    ],
    "https": [
        "Verify TLS version — disable TLS 1.0 and 1.1, enforce TLS 1.2 minimum.",
        "Check SSL certificate validity and expiry date.",
        "Run an SSL Labs scan (ssllabs.com) to check for weak cipher suites.",
        "Ensure HSTS header is present with a long max-age value.",
    ],
    "mysql": [
        "Bind MySQL to localhost (127.0.0.1) — it should not listen on external interfaces.",
        "If remote access is required, restrict to specific IP addresses only.",
        "Ensure the root account has a strong password and remote root login is disabled.",
        "Audit all MySQL user accounts and remove unused accounts.",
        "Enable MySQL audit logging to record all queries.",
    ],
    "mssql": [
        "Restrict SQL Server access to application servers only — firewall port 1433.",
        "Disable the SA account or change its password to a strong credential.",
        "Disable SQL Server Browser service if not needed.",
        "Enable SQL Server Audit to log authentication events.",
    ],
    "postgresql": [
        "Restrict PostgreSQL to localhost unless remote access is explicitly required.",
        "Review pg_hba.conf to ensure authentication methods are secure.",
        "Audit all database roles and remove unnecessary superuser privileges.",
        "Enable SSL connections and disable plain text connections.",
    ],
    "mongodb": [
        "Enable MongoDB authentication immediately — older versions default to no auth.",
        "Bind to localhost or specific IPs — remove 0.0.0.0 binding.",
        "Enable TLS/SSL for all connections.",
        "Audit existing databases for any publicly exposed data.",
    ],
    "redis": [
        "Enable Redis authentication using the requirepass directive.",
        "Bind Redis to localhost only — never expose to external interfaces.",
        "Disable dangerous commands: FLUSHALL, CONFIG, SLAVEOF using rename-command.",
        "Run Redis as a non-root user.",
    ],
    "rdp": [
        "Restrict RDP access to a VPN or specific trusted IP ranges only.",
        "Enable Network Level Authentication (NLA).",
        "Ensure the system is patched against BlueKeep (CVE-2019-0708).",
        "Enable account lockout policies to prevent brute-force attacks.",
        "Consider changing RDP from the default port 3389.",
    ],
    "vnc": [
        "Set a strong VNC password — default or blank passwords are common.",
        "Restrict VNC access to localhost and tunnel through SSH.",
        "Upgrade to a VNC implementation that supports TLS encryption.",
        "Disable VNC if it is not actively required.",
    ],
    "smb": [
        "Ensure the system is patched against EternalBlue (MS17-010 / CVE-2017-0144).",
        "Disable SMBv1 — it is insecure and should not be in use.",
        "Block ports 445 and 139 at the perimeter firewall.",
        "Enable SMB signing to prevent relay attacks.",
        "Audit SMB shares for excessive permissions.",
    ],
    "smtp": [
        "Test the server for open relay configuration using an external tool.",
        "Implement SPF, DKIM, and DMARC DNS records.",
        "Enforce TLS for all SMTP connections (STARTTLS).",
        "Restrict SMTP access to authorised mail servers only.",
    ],
    "snmp": [
        "Change default community strings ('public', 'private') immediately.",
        "Upgrade to SNMPv3 with authentication and encryption.",
        "Restrict SNMP access to monitoring servers only using ACLs.",
        "If SNMP is not needed, disable the service entirely.",
    ],
    "ldap": [
        "Disable anonymous LDAP bind — require authentication for all queries.",
        "Use LDAPS (LDAP over TLS) on port 636 instead of plain LDAP on 389.",
        "Audit LDAP directory permissions — apply least-privilege access.",
        "Monitor LDAP logs for unusual enumeration activity.",
    ],
    "pop3": [
        "Migrate users to POP3S (POP3 over TLS on port 995).",
        "Disable plain POP3 on port 110 at the server level.",
        "Consider migrating to IMAP with TLS for better security.",
    ],
    "imap": [
        "Disable plain IMAP on port 143 — enforce IMAPS (port 993) with TLS.",
        "Implement account lockout after failed authentication attempts.",
        "Ensure mail server software is patched to the latest version.",
    ],
    "dns": [
        "Disable DNS zone transfers to unauthorised hosts.",
        "Test for zone transfer vulnerability: dig AXFR @<target>",
        "Implement DNSSEC if serving authoritative DNS.",
        "Restrict recursive DNS queries to internal clients only.",
    ],
}

# Used when we don't have specific steps for a service
DEFAULT_REMEDIATION: List[str] = [
    "Verify this service is intentionally exposed and document the business reason.",
    "Ensure the service is running the latest patched version.",
    "Restrict access to authorised IP ranges using firewall rules.",
    "Enable service-level logging and monitor for unusual activity.",
]


class ReportGenerator:
    """
    Builds a standalone HTML assessment report from risk findings.

    The output is a single file with no external dependencies — CSS is inline,
    no JavaScript frameworks, nothing to install. Open it in any browser.
    """

    def __init__(self, target: str, output_dir: str = "reports"):
        self.target     = target
        self.output_dir = output_dir

    def _get_recommendations(self, service: str) -> List[str]:
        """Returns remediation steps for a service, falling back to generic advice."""
        return REMEDIATION_MAP.get(service.lower(), DEFAULT_REMEDIATION)

    def _risk_badge_colour(self, level: str) -> str:
        """CSS colour for a risk level badge."""
        return {
            "CRITICAL": "#ff4444",
            "HIGH":     "#ff8800",
            "MEDIUM":   "#ffcc00",
            "LOW":      "#44aaff",
            "INFO":     "#aaaaaa",
        }.get(level.upper(), "#aaaaaa")

    def _build_html(self, risks: List[Dict], scan_date: str) -> str:
        """Builds the full HTML document string. All CSS is inline — no external deps."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for r in risks:
            level = r.get("risk_level", "INFO").upper()
            if level in counts:
                counts[level] += 1

        findings_html = ""
        for r in risks:
            port      = r.get("port", "?")
            protocol  = r.get("protocol", "tcp")
            service   = r.get("service", "unknown")
            level     = r.get("risk_level", "INFO").upper()
            reason    = r.get("risk_reason", "")
            version   = r.get("version", "Unknown")
            banner    = r.get("banner", "—")
            colour    = self._risk_badge_colour(level)
            rec_steps = self._get_recommendations(service)
            rec_items = "".join(f"<li>{step}</li>" for step in rec_steps)

            findings_html += f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="port-label">{port}/{protocol}</span>
                    <span class="service-label">{service}</span>
                    <span class="badge" style="background:{colour}">{level}</span>
                </div>
                <div class="finding-body">
                    <p class="reason">{reason}</p>
                    <div class="detail-row">
                        <span class="detail-label">Version</span>
                        <span class="detail-value">{version}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-label">Banner</span>
                        <span class="detail-value code">{banner}</span>
                    </div>
                    <div class="recommendations">
                        <p class="rec-title">Remediation Steps</p>
                        <ol>{rec_items}</ol>
                    </div>
                </div>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Assessment Report — {self.target}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 32px 24px;
            max-width: 960px;
            margin: 0 auto;
            font-size: 14px;
            line-height: 1.6;
        }}

        .header {{
            border-bottom: 1px solid #30363d;
            padding-bottom: 24px;
            margin-bottom: 32px;
        }}
        .header h1 {{ font-size: 22px; font-weight: 600; color: #58a6ff; margin-bottom: 6px; }}
        .header .meta {{ color: #8b949e; font-size: 13px; display: flex; gap: 24px; flex-wrap: wrap; margin-top: 12px; }}
        .header .meta span b {{ color: #c9d1d9; }}

        .summary {{ display: flex; gap: 12px; margin-bottom: 40px; flex-wrap: wrap; }}
        .summary-card {{
            flex: 1; min-width: 100px;
            background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center;
        }}
        .summary-card .count {{ font-size: 28px; font-weight: 700; line-height: 1.1; }}
        .summary-card .label {{ font-size: 11px; color: #8b949e; text-transform: uppercase; letter-spacing: 0.08em; margin-top: 4px; }}

        h2 {{ font-size: 15px; font-weight: 600; color: #58a6ff; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #21262d; }}

        .finding {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 16px; overflow: hidden; }}
        .finding-header {{ display: flex; align-items: center; gap: 12px; padding: 14px 18px; background: #1c2128; border-bottom: 1px solid #30363d; }}
        .port-label {{ font-family: "Courier New", monospace; font-size: 13px; color: #79c0ff; font-weight: 600; min-width: 90px; }}
        .service-label {{ font-size: 13px; color: #e6edf3; flex: 1; font-weight: 500; }}
        .badge {{ padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; color: #0d1117; letter-spacing: 0.05em; }}
        .finding-body {{ padding: 16px 18px; }}
        .reason {{ color: #8b949e; font-size: 13px; margin-bottom: 12px; }}
        .detail-row {{ display: flex; gap: 12px; margin-bottom: 6px; font-size: 12px; }}
        .detail-label {{ color: #8b949e; min-width: 56px; }}
        .detail-value {{ color: #c9d1d9; }}
        .detail-value.code {{ font-family: "Courier New", monospace; color: #79c0ff; word-break: break-all; }}
        .recommendations {{ margin-top: 14px; background: #0d1117; border: 1px solid #21262d; border-radius: 6px; padding: 12px 16px; }}
        .rec-title {{ font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.08em; color: #3fb950; margin-bottom: 8px; }}
        ol {{ padding-left: 18px; }}
        ol li {{ font-size: 12px; color: #8b949e; margin-bottom: 4px; line-height: 1.5; }}

        .footer {{ margin-top: 48px; padding-top: 16px; border-top: 1px solid #21262d; color: #484f58; font-size: 12px; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 8px; }}
    </style>
</head>
<body>

    <div class="header">
        <h1>Attack Surface Assessment Report</h1>
        <div class="meta">
            <span><b>Target</b> &nbsp; {self.target}</span>
            <span><b>Date</b> &nbsp; {scan_date}</span>
            <span><b>Findings</b> &nbsp; {len(risks)}</span>
            <span><b>Tool</b> &nbsp; Cyber Attack Surface Assessment Framework</span>
        </div>
    </div>

    <h2>Executive Summary</h2>
    <div class="summary">
        <div class="summary-card"><div class="count" style="color:#ff4444">{counts["CRITICAL"]}</div><div class="label">Critical</div></div>
        <div class="summary-card"><div class="count" style="color:#ff8800">{counts["HIGH"]}</div><div class="label">High</div></div>
        <div class="summary-card"><div class="count" style="color:#ffcc00">{counts["MEDIUM"]}</div><div class="label">Medium</div></div>
        <div class="summary-card"><div class="count" style="color:#44aaff">{counts["LOW"]}</div><div class="label">Low</div></div>
        <div class="summary-card"><div class="count" style="color:#aaaaaa">{counts["INFO"]}</div><div class="label">Info</div></div>
    </div>

    <h2>Findings</h2>
    {findings_html}

    <div class="footer">
        <span>Cyber Attack Surface Assessment Framework</span>
        <span>Generated {scan_date}</span>
    </div>

</body>
</html>"""

    def generate(self, risks: List[Dict]) -> Optional[str]:
        """
        Writes the HTML report to reports/<target>_report_<timestamp>.html.
        Returns the file path, or None if generation failed.
        """
        if not risks:
            print(f"{RED}[-] No findings to report{RESET}")
            return None

        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for r in risks:
            r["recommendations"] = self._get_recommendations(r.get("service", ""))

        try:
            os.makedirs(self.output_dir, exist_ok=True)

            timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_target = self.target.replace(".", "_")
            filename    = f"{safe_target}_report_{timestamp}.html"
            filepath    = os.path.join(self.output_dir, filename)

            with open(filepath, "w", encoding="utf-8") as f:
                f.write(self._build_html(risks, scan_date))

            print(f"{GREEN}[+] Report generated → {filepath}{RESET}")
            return filepath

        except OSError as e:
            print(f"{RED}[-] Failed to generate report: {e}{RESET}")
            return None

    def display_summary(self, risks: List[Dict]) -> None:
        """
        Prints a quick terminal summary of the top remediation actions.
        Only shows CRITICAL and HIGH findings — the full details are in the HTML report.
        """
        if not risks:
            print(f"{RED}[-] No findings to summarise{RESET}")
            return

        priority = [r for r in risks if r.get("risk_level") in ("CRITICAL", "HIGH")]

        print(f"{BOLD}{GREEN}[+] Priority Remediation Actions{RESET}\n")

        if not priority:
            print(f"  {CYAN}No CRITICAL or HIGH findings — good posture on this target.{RESET}\n")
            return

        for r in priority:
            port     = r.get("port", "?")
            protocol = r.get("protocol", "tcp")
            service  = r.get("service", "unknown")
            level    = r.get("risk_level", "")
            colour   = RED if level == "CRITICAL" else YELLOW

            print(f"  {colour}{BOLD}{level}{RESET}  {CYAN}{port}/{protocol}{RESET}  {service}")

            steps = self._get_recommendations(service)
            for i, step in enumerate(steps[:2], 1):  # show top 2 steps in terminal
                print(f"    {i}. {step}")
            print()
