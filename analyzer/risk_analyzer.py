import json
import os
from datetime import datetime
from utils.colors import GREEN, RED, YELLOW, CYAN, BLUE, BOLD, RESET

LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SCORES = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
COLORS = {"CRITICAL": RED + BOLD, "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN, "INFO": BLUE}

# (risk level, reason) keyed by service name
SERVICE_RISK = {
    "telnet":     ("CRITICAL", "unencrypted remote access — all traffic visible on the network"),
    "rsh":        ("CRITICAL", "legacy remote shell — no auth encryption"),
    "rlogin":     ("CRITICAL", "legacy remote login — no auth encryption"),
    "mongodb":    ("CRITICAL", "NoSQL db — older versions default to no auth"),
    "redis":      ("CRITICAL", "in-memory db — often misconfigured with no auth"),

    "ftp":        ("HIGH",     "unencrypted file transfer — creds in plain text"),
    "mysql":      ("HIGH",     "database exposed — verify not internet-facing"),
    "mssql":      ("HIGH",     "database exposed — verify not internet-facing"),
    "postgresql": ("HIGH",     "database exposed — verify not internet-facing"),
    "cassandra":  ("HIGH",     "distributed db — verify auth is enabled"),
    "rdp":        ("HIGH",     "remote desktop — high-value target, check for BlueKeep"),
    "vnc":        ("HIGH",     "remote desktop — check for weak/missing auth"),
    "smb":        ("HIGH",     "file sharing — check for EternalBlue (MS17-010)"),
    "snmp":       ("HIGH",     "network mgmt — check for default community strings"),
    "tftp":       ("HIGH",     "trivial FTP — no auth, no encryption"),

    "netbios":    ("MEDIUM",   "can leak hostname, OS, and user info"),
    "smtp":       ("MEDIUM",   "mail server — verify not configured as open relay"),
    "pop3":       ("MEDIUM",   "unencrypted mail — creds in plain text"),
    "imap":       ("MEDIUM",   "unencrypted mail — creds in plain text"),
    "ldap":       ("MEDIUM",   "directory service — check for anonymous bind"),
    "teamviewer": ("MEDIUM",   "remote management — verify access controls"),

    "http":       ("LOW",      "HTTP — check for HTTPS redirect and security headers"),
    "http-alt":   ("LOW",      "alternate HTTP port — verify exposure is intentional"),
    "ssh":        ("LOW",      "secure shell — verify version, disable password auth"),
    "dns":        ("LOW",      "DNS — check for zone transfer vulnerability"),

    "https":      ("INFO",     "encrypted web — verify TLS version and certificate"),
}

# secondary lookup by port number — catches misidentified services
PORT_RISK = {
    23:    ("CRITICAL", "port 23 — telnet, unencrypted"),
    6379:  ("CRITICAL", "port 6379 — redis, often no auth"),
    9200:  ("CRITICAL", "port 9200 — elasticsearch, often no auth"),
    27017: ("CRITICAL", "port 27017 — mongodb, often no auth"),

    445:   ("HIGH",     "port 445 — SMB, check for EternalBlue"),
    1433:  ("HIGH",     "port 1433 — MSSQL"),
    1521:  ("HIGH",     "port 1521 — Oracle db"),
    3306:  ("HIGH",     "port 3306 — MySQL"),
    3389:  ("HIGH",     "port 3389 — RDP"),
    5432:  ("HIGH",     "port 5432 — PostgreSQL"),
    5900:  ("HIGH",     "port 5900 — VNC"),
}


class RiskAnalyzer:
    def __init__(self, target, output_dir="scans"):
        self.target     = target
        self.output_dir = output_dir

    def _score(self, svc):
        port       = svc.get("port", 0)
        service    = svc.get("service", "unknown").lower()
        confidence = svc.get("confidence", "LOW")

        by_name = SERVICE_RISK.get(service)
        by_port = PORT_RISK.get(port)

        # take whichever lookup gives the worse score
        if by_name and by_port:
            level, reason = by_name if SCORES[by_name[0]] >= SCORES[by_port[0]] else by_port
        elif by_name:
            level, reason = by_name
        elif by_port:
            level, reason = by_port
        else:
            level  = "INFO"
            reason = f"'{service}' on port {port} — manual review recommended"

        # low confidence means we couldn't confirm the service, so dial it back one step
        if confidence == "LOW":
            level   = LEVELS[min(LEVELS.index(level) + 1, len(LEVELS) - 1)]
            reason += " [low confidence — verify manually]"

        return level, reason

    def analyze(self, services):
        if not services:
            print(f"{RED}[-] no services to analyze{RESET}")
            return []

        print(f"{YELLOW}[*] scoring {len(services)} service(s)...{RESET}\n")
        results = []
        for svc in services:
            level, reason = self._score(svc)
            results.append({
                **svc,
                "risk_level":  level,
                "risk_score":  SCORES[level],
                "risk_reason": reason,
                "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

        return sorted(results, key=lambda x: x["risk_score"], reverse=True)

    def export_json(self, results):
        if not results:
            return None
        os.makedirs(self.output_dir, exist_ok=True)
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.output_dir, f"{self.target.replace('.', '_')}_risks_{ts}.json")

        counts = {l: sum(1 for r in results if r["risk_level"] == l) for l in LEVELS}
        data   = {
            "meta": {"target": self.target, "exported_at": ts, "total": len(results), **counts},
            "findings": results,
        }
        try:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2, default=str)
            print(f"{GREEN}[+] risks → {filepath}{RESET}")
            return filepath
        except OSError as e:
            print(f"{RED}[-] couldn't write json: {e}{RESET}")
            return None

    def display_results(self, results):
        if not results:
            print(f"{RED}[-] nothing to show{RESET}")
            return

        print(f"{BOLD}{GREEN}[+] risk analysis — {self.target}{RESET}\n")
        print(f"  {CYAN}{'PORT':<12}{'SERVICE':<12}{'LEVEL':<12}REASON{RESET}")
        print(f"  {BLUE}{'─' * 70}{RESET}")

        for r in results:
            col = COLORS.get(r["risk_level"], RESET)
            print(
                f"  {GREEN}{r['port']}/{r['protocol']:<8}{RESET}"
                f"{CYAN}{r['service']:<12}{RESET}"
                f"{col}{r['risk_level']:<12}{RESET}"
                f"{r['risk_reason'][:52]}"
            )

        counts = {l: sum(1 for r in results if r["risk_level"] == l) for l in LEVELS}
        print(f"\n  {BOLD}{CYAN}── summary {'─' * 30}{RESET}")
        for level in LEVELS:
            col = COLORS.get(level, RESET)
            print(f"  {col}{level:<10}{RESET}  {counts[level]:>2}  {col}{'█' * counts[level]}{RESET}")
        print()
