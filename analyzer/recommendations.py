import os
from datetime import datetime
from utils.colors import GREEN, RED, YELLOW, CYAN, BOLD, RESET

# concrete steps per service — not "keep software updated", actual actions
REMEDIATION = {
    "telnet": [
        "Disable telnet immediately — there's no legitimate use for it in 2024.",
        "Replace with SSH for all remote access.",
        "Block port 23 at the firewall.",
        "Rotate all passwords that may have been sent over telnet.",
    ],
    "ftp": [
        "Disable plain FTP and switch to SFTP or FTPS.",
        "If FTP must stay, enforce TLS and disable anonymous access.",
        "Restrict access to specific IPs via firewall.",
        "Review FTP logs for unauthorized access.",
    ],
    "ssh": [
        "Disable password auth — keys only.",
        "Make sure you're running a recent OpenSSH (8.x+).",
        "Consider moving off port 22 to cut down on automated scans.",
        "Set up fail2ban or similar to block brute-force attempts.",
    ],
    "http": [
        "Redirect all HTTP to HTTPS with a 301.",
        "Add HSTS so browsers enforce HTTPS going forward.",
        "Strip the Server: header — no need to advertise your stack.",
        "Check that directory listing is off.",
    ],
    "https": [
        "Disable TLS 1.0 and 1.1 — enforce 1.2 minimum, prefer 1.3.",
        "Check cert validity and expiry.",
        "Run an SSL Labs scan to find weak cipher suites.",
        "Make sure HSTS is set with a long max-age.",
    ],
    "mysql": [
        "Bind MySQL to 127.0.0.1 — it should never listen on an external interface.",
        "If remote access is needed, lock it down to specific IPs.",
        "Disable remote root login and set a strong root password.",
        "Audit user accounts and drop anything unused.",
    ],
    "mssql": [
        "Firewall port 1433 to application servers only.",
        "Disable the SA account or change its password.",
        "Disable SQL Server Browser if not needed.",
        "Enable auditing for authentication events.",
    ],
    "postgresql": [
        "Bind to localhost unless remote access is explicitly required.",
        "Review pg_hba.conf — make sure auth methods are sane.",
        "Audit roles and remove unnecessary superuser grants.",
        "Enable SSL connections.",
    ],
    "mongodb": [
        "Enable authentication — older versions ship with it off.",
        "Bind to localhost or specific IPs, not 0.0.0.0.",
        "Enable TLS for all connections.",
        "Audit existing databases for exposed data.",
    ],
    "redis": [
        "Set requirepass in redis.conf.",
        "Bind to localhost only.",
        "Rename or disable dangerous commands: FLUSHALL, CONFIG, SLAVEOF.",
        "Run Redis as a non-root user.",
    ],
    "rdp": [
        "Put RDP behind a VPN — it should not be open to the internet.",
        "Enable Network Level Authentication (NLA).",
        "Patch for BlueKeep (CVE-2019-0708) if not already done.",
        "Set account lockout to stop brute-force attempts.",
    ],
    "vnc": [
        "Set a strong password — blank/default VNC auth is common.",
        "Tunnel through SSH instead of exposing VNC directly.",
        "Upgrade to a VNC implementation with TLS.",
        "Disable VNC if it's not actively in use.",
    ],
    "smb": [
        "Patch for EternalBlue (MS17-010 / CVE-2017-0144).",
        "Disable SMBv1.",
        "Block ports 445 and 139 at the perimeter.",
        "Enable SMB signing to stop relay attacks.",
    ],
    "smtp": [
        "Test for open relay with an external tool.",
        "Add SPF, DKIM, and DMARC records.",
        "Enforce STARTTLS.",
        "Restrict SMTP to authorised mail servers.",
    ],
    "snmp": [
        "Change community strings from 'public'/'private' immediately.",
        "Upgrade to SNMPv3 with auth and encryption.",
        "Restrict SNMP access to your monitoring server IPs.",
        "Disable SNMP entirely if you're not using it.",
    ],
    "ldap": [
        "Disable anonymous bind.",
        "Switch to LDAPS (port 636) — plain LDAP on 389 sends creds in the clear.",
        "Tighten directory permissions — least privilege.",
        "Watch LDAP logs for enumeration activity.",
    ],
    "pop3": [
        "Move to POP3S on port 995.",
        "Disable plain POP3 on port 110.",
    ],
    "imap": [
        "Disable plain IMAP on 143 — use IMAPS (993) with TLS.",
        "Add account lockout after failed logins.",
    ],
    "dns": [
        "Disable zone transfers to unauthorised hosts.",
        "Test: dig AXFR @<target>",
        "Enable DNSSEC if running authoritative DNS.",
        "Restrict recursive queries to internal clients.",
    ],
}

DEFAULT_STEPS = [
    "Verify this service is intentionally exposed and document why.",
    "Make sure it's running the latest patched version.",
    "Restrict access to known IP ranges.",
    "Enable logging and watch for unusual activity.",
]

BADGE_COLOR = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#44aaff",
    "INFO":     "#aaaaaa",
}


class ReportGenerator:
    def __init__(self, target, output_dir="reports"):
        self.target     = target
        self.output_dir = output_dir

    def generate(self, risks):
        if not risks:
            print(f"{RED}[-] no findings to report{RESET}")
            return None

        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for r in risks:
            r["steps"] = REMEDIATION.get(r.get("service", ""), DEFAULT_STEPS)

        os.makedirs(self.output_dir, exist_ok=True)
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.output_dir, f"{self.target.replace('.', '_')}_report_{ts}.html")

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(self._html(risks, scan_date))
            print(f"{GREEN}[+] report → {filepath}{RESET}")
            return filepath
        except OSError as e:
            print(f"{RED}[-] couldn't write report: {e}{RESET}")
            return None

    def display_summary(self, risks):
        priority = [r for r in risks if r.get("risk_level") in ("CRITICAL", "HIGH")]

        print(f"{BOLD}{GREEN}[+] priority actions{RESET}\n")
        if not priority:
            print(f"  {CYAN}no CRITICAL or HIGH findings — looking good.{RESET}\n")
            return

        for r in priority:
            col   = RED if r["risk_level"] == "CRITICAL" else YELLOW
            steps = REMEDIATION.get(r.get("service", ""), DEFAULT_STEPS)
            print(f"  {col}{BOLD}{r['risk_level']}{RESET}  {CYAN}{r['port']}/{r['protocol']}{RESET}  {r['service']}")
            for i, step in enumerate(steps[:2], 1):
                print(f"    {i}. {step}")
            print()

    def _html(self, risks, scan_date):
        counts = {l: 0 for l in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        for r in risks:
            counts[r.get("risk_level", "INFO")] += 1

        cards = ""
        for r in risks:
            port    = r.get("port", "?")
            proto   = r.get("protocol", "tcp")
            service = r.get("service", "unknown")
            level   = r.get("risk_level", "INFO")
            reason  = r.get("risk_reason", "")
            version = r.get("version", "Unknown")
            banner  = r.get("banner", "—")
            color   = BADGE_COLOR.get(level, "#aaaaaa")
            steps   = "".join(f"<li>{s}</li>" for s in r.get("steps", DEFAULT_STEPS))

            cards += f"""
            <div class="card">
                <div class="card-head">
                    <span class="port">{port}/{proto}</span>
                    <span class="svc">{service}</span>
                    <span class="badge" style="background:{color}">{level}</span>
                </div>
                <div class="card-body">
                    <p class="reason">{reason}</p>
                    <div class="row"><span class="lbl">Version</span><span>{version}</span></div>
                    <div class="row"><span class="lbl">Banner</span><span class="mono">{banner}</span></div>
                    <div class="steps">
                        <p class="steps-title">Remediation</p>
                        <ol>{steps}</ol>
                    </div>
                </div>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Assessment — {self.target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          background: #0d1117; color: #c9d1d9; padding: 32px 24px;
          max-width: 960px; margin: 0 auto; font-size: 14px; line-height: 1.6; }}

  .header {{ border-bottom: 1px solid #30363d; padding-bottom: 24px; margin-bottom: 32px; }}
  .header h1 {{ font-size: 22px; color: #58a6ff; margin-bottom: 6px; }}
  .meta {{ color: #8b949e; font-size: 13px; display: flex; gap: 24px; flex-wrap: wrap; margin-top: 12px; }}
  .meta b {{ color: #c9d1d9; }}

  .summary {{ display: flex; gap: 12px; margin-bottom: 40px; flex-wrap: wrap; }}
  .tile {{ flex: 1; min-width: 90px; background: #161b22; border: 1px solid #30363d;
            border-radius: 8px; padding: 16px; text-align: center; }}
  .tile .n {{ font-size: 28px; font-weight: 700; line-height: 1.1; }}
  .tile .l {{ font-size: 11px; color: #8b949e; text-transform: uppercase;
               letter-spacing: .08em; margin-top: 4px; }}

  h2 {{ font-size: 15px; color: #58a6ff; margin-bottom: 16px; padding-bottom: 8px;
        border-bottom: 1px solid #21262d; }}

  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
            margin-bottom: 16px; overflow: hidden; }}
  .card-head {{ display: flex; align-items: center; gap: 12px; padding: 14px 18px;
                background: #1c2128; border-bottom: 1px solid #30363d; }}
  .port {{ font-family: monospace; font-size: 13px; color: #79c0ff; font-weight: 600; min-width: 90px; }}
  .svc  {{ font-size: 13px; flex: 1; font-weight: 500; }}
  .badge {{ padding: 3px 10px; border-radius: 12px; font-size: 11px;
             font-weight: 700; color: #0d1117; letter-spacing: .05em; }}

  .card-body {{ padding: 16px 18px; }}
  .reason {{ color: #8b949e; font-size: 13px; margin-bottom: 12px; }}
  .row {{ display: flex; gap: 12px; margin-bottom: 6px; font-size: 12px; }}
  .lbl {{ color: #8b949e; min-width: 56px; }}
  .mono {{ font-family: monospace; color: #79c0ff; word-break: break-all; }}

  .steps {{ margin-top: 14px; background: #0d1117; border: 1px solid #21262d;
             border-radius: 6px; padding: 12px 16px; }}
  .steps-title {{ font-size: 11px; font-weight: 600; text-transform: uppercase;
                   letter-spacing: .08em; color: #3fb950; margin-bottom: 8px; }}
  ol {{ padding-left: 18px; }}
  li {{ font-size: 12px; color: #8b949e; margin-bottom: 4px; }}

  .footer {{ margin-top: 48px; padding-top: 16px; border-top: 1px solid #21262d;
              color: #484f58; font-size: 12px; display: flex;
              justify-content: space-between; flex-wrap: wrap; gap: 8px; }}
</style>
</head>
<body>

<div class="header">
  <h1>Attack Surface Assessment</h1>
  <div class="meta">
    <span><b>Target</b> &nbsp;{self.target}</span>
    <span><b>Date</b> &nbsp;{scan_date}</span>
    <span><b>Findings</b> &nbsp;{len(risks)}</span>
  </div>
</div>

<h2>Summary</h2>
<div class="summary">
  <div class="tile"><div class="n" style="color:#ff4444">{counts['CRITICAL']}</div><div class="l">Critical</div></div>
  <div class="tile"><div class="n" style="color:#ff8800">{counts['HIGH']}</div><div class="l">High</div></div>
  <div class="tile"><div class="n" style="color:#ffcc00">{counts['MEDIUM']}</div><div class="l">Medium</div></div>
  <div class="tile"><div class="n" style="color:#44aaff">{counts['LOW']}</div><div class="l">Low</div></div>
  <div class="tile"><div class="n" style="color:#aaaaaa">{counts['INFO']}</div><div class="l">Info</div></div>
</div>

<h2>Findings</h2>
{cards}

<div class="footer">
  <span>Cyber Attack Surface Assessment Framework</span>
  <span>Generated {scan_date}</span>
</div>

</body>
</html>"""
