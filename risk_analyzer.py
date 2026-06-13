"""
risk_analyzer.py — Phase 4: scores each service finding by risk level.

Takes the enriched service data from Phase 3 and classifies every open port as
CRITICAL, HIGH, MEDIUM, LOW, or INFO based on what's running and how exposed it is.
Results are sorted with the worst findings first so the report leads with what matters.

Usage:
    from analyzer.risk_analyzer import RiskAnalyzer

    ra = RiskAnalyzer(target="192.168.56.101")
    results = ra.analyze(services)
    ra.display_results(results)
    ra.export_json(results)
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple

GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

RISK_COLOURS = {
    CRITICAL: RED + BOLD,
    HIGH:     RED,
    MEDIUM:   YELLOW,
    LOW:      CYAN,
    INFO:     BLUE,
}

# Numeric values make it easy to compare and sort risk levels
RISK_SCORES = {
    CRITICAL: 4,
    HIGH:     3,
    MEDIUM:   2,
    LOW:      1,
    INFO:     0,
}

# Service name → (risk level, reason)
# These reflect real-world risk — telnet is always bad, https is usually fine.
SERVICE_RISK_MAP: Dict[str, Tuple[str, str]] = {
    # Unencrypted remote access — basically unacceptable in 2024
    "telnet":     (CRITICAL, "Unencrypted remote access — all traffic visible on network"),
    "ftp":        (HIGH,     "Unencrypted file transfer — credentials sent in plain text"),
    "rsh":        (CRITICAL, "Legacy remote shell — no authentication encryption"),
    "rlogin":     (CRITICAL, "Legacy remote login — no authentication encryption"),

    # Databases shouldn't be exposed to the network at all
    "mysql":      (HIGH,     "Database service exposed — verify not internet-facing"),
    "mssql":      (HIGH,     "Database service exposed — verify not internet-facing"),
    "postgresql": (HIGH,     "Database service exposed — verify not internet-facing"),
    "mongodb":    (CRITICAL, "NoSQL database — historically exposed with no auth by default"),
    "redis":      (CRITICAL, "In-memory database — often misconfigured with no auth"),
    "cassandra":  (HIGH,     "Distributed database — verify authentication is enabled"),

    # Remote desktop is a high-value target for attackers
    "rdp":        (HIGH,     "Remote desktop — high-value target, verify patch level (BlueKeep)"),
    "vnc":        (HIGH,     "Remote desktop — check for weak or missing authentication"),
    "teamviewer": (MEDIUM,   "Remote management tool — verify access controls"),

    # File sharing
    "smb":        (HIGH,     "File sharing — check for EternalBlue (MS17-010) vulnerability"),
    "netbios":    (MEDIUM,   "NetBIOS — can leak hostname, OS, and user information"),

    # Mail
    "smtp":       (MEDIUM,   "Mail server — verify it is not configured as an open relay"),
    "pop3":       (MEDIUM,   "Unencrypted mail retrieval — credentials in plain text"),
    "imap":       (MEDIUM,   "Unencrypted mail access — credentials in plain text"),

    # Network management
    "snmp":       (HIGH,     "Network management — check for default community strings"),
    "tftp":       (HIGH,     "Trivial FTP — unauthenticated, no encryption"),

    # Directory services
    "ldap":       (MEDIUM,   "Directory service — check for anonymous bind vulnerability"),

    # Web — needs manual testing but isn't inherently dangerous
    "http":       (LOW,      "Web service on HTTP — check for HTTPS redirect and headers"),
    "https":      (INFO,     "Encrypted web service — verify TLS version and certificate"),
    "http-alt":   (LOW,      "Alternate HTTP port — verify this exposure is intentional"),

    # These are generally fine but still worth noting
    "ssh":        (LOW,      "Secure shell — verify version and disable password auth"),
    "dns":        (LOW,      "DNS service — check for zone transfer vulnerability"),
}

# Port numbers as a secondary lookup — catches cases where nmap misidentifies a service
PORT_RISK_MAP: Dict[int, Tuple[str, str]] = {
    23:    (CRITICAL, "Port 23 — Telnet, unencrypted remote access"),
    445:   (HIGH,     "Port 445 — SMB, check for EternalBlue (MS17-010)"),
    1433:  (HIGH,     "Port 1433 — MSSQL database exposed"),
    1521:  (HIGH,     "Port 1521 — Oracle database exposed"),
    3306:  (HIGH,     "Port 3306 — MySQL database exposed"),
    3389:  (HIGH,     "Port 3389 — RDP, remote desktop exposed"),
    5432:  (HIGH,     "Port 5432 — PostgreSQL database exposed"),
    5900:  (HIGH,     "Port 5900 — VNC remote desktop exposed"),
    6379:  (CRITICAL, "Port 6379 — Redis, often no authentication by default"),
    9200:  (CRITICAL, "Port 9200 — Elasticsearch, often no authentication by default"),
    27017: (CRITICAL, "Port 27017 — MongoDB, often no authentication by default"),
}


class RiskAnalyzer:
    """
    Scores each service finding using service name, port number, and confidence level.

    The final risk level is the higher of the service-name lookup and port-number lookup.
    LOW-confidence results are downgraded one step to avoid false alarms from
    cases where nmap guessed the service without us being able to confirm it.
    """

    def __init__(self, target: str, output_dir: str = "scans"):
        self.target     = target
        self.output_dir = output_dir

    def _score_by_service(self, service: str) -> Optional[Tuple[str, str]]:
        """Looks up risk for a service name. Returns None if it's not in the map."""
        return SERVICE_RISK_MAP.get(service.lower())

    def _score_by_port(self, port: int) -> Optional[Tuple[str, str]]:
        """Looks up risk for a port number. Returns None if it's not in the map."""
        return PORT_RISK_MAP.get(port)

    def _downgrade_confidence(self, level: str) -> str:
        """
        Drops a risk level one step down the chain (CRITICAL → HIGH → MEDIUM → LOW → INFO).
        Used when we aren't confident the identified service is actually what's running.
        """
        chain = [CRITICAL, HIGH, MEDIUM, LOW, INFO]
        idx = chain.index(level) if level in chain else len(chain) - 1
        return chain[min(idx + 1, len(chain) - 1)]

    def _calculate_risk(self, service_result: Dict) -> Tuple[str, str]:
        """
        Calculates the final risk level for a single finding.

        Takes whichever is higher between the service-name and port-number lookups,
        then downgrades by one step if confidence is LOW.
        Defaults to INFO for anything not in either map.
        """
        port       = service_result.get("port", 0)
        service    = service_result.get("service", "unknown")
        confidence = service_result.get("confidence", "LOW")

        service_risk = self._score_by_service(service)
        port_risk    = self._score_by_port(port)

        if service_risk and port_risk:
            # Pick whichever score is higher
            if RISK_SCORES[service_risk[0]] >= RISK_SCORES[port_risk[0]]:
                level, reason = service_risk
            else:
                level, reason = port_risk
        elif service_risk:
            level, reason = service_risk
        elif port_risk:
            level, reason = port_risk
        else:
            level  = INFO
            reason = f"Service '{service}' on port {port} — manual review recommended"

        if confidence == "LOW":
            level = self._downgrade_confidence(level)
            reason += " [confidence LOW — manual verification needed]"

        return level, reason

    def analyze(self, services: List[Dict]) -> List[Dict]:
        """
        Scores all service findings and returns risk-annotated results, worst first.

        Each dict gets three new fields:
            risk_level  — CRITICAL / HIGH / MEDIUM / LOW / INFO
            risk_score  — numeric version of the above (4 = CRITICAL, 0 = INFO)
            risk_reason — plain-English explanation
        """
        if not services:
            print(f"{RED}[-] No services provided for risk analysis{RESET}")
            return []

        print(f"{YELLOW}[*] Analysing risk for {len(services)} service(s) on {self.target}...{RESET}\n")

        results = []
        for svc in services:
            level, reason = self._calculate_risk(svc)
            results.append({
                **svc,
                "risk_level":   level,
                "risk_score":   RISK_SCORES[level],
                "risk_reason":  reason,
                "analyzed_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            })

        return sorted(results, key=lambda x: x["risk_score"], reverse=True)

    def export_json(self, results: List[Dict]) -> Optional[str]:
        """Saves risk analysis results to scans/ as a timestamped JSON file."""
        if not results:
            print(f"{YELLOW}[!] No results to export{RESET}")
            return None

        try:
            os.makedirs(self.output_dir, exist_ok=True)

            timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_target = self.target.replace(".", "_")
            filename    = f"{safe_target}_risks_{timestamp}.json"
            filepath    = os.path.join(self.output_dir, filename)

            level_counts = {lvl: 0 for lvl in [CRITICAL, HIGH, MEDIUM, LOW, INFO]}
            for r in results:
                level_counts[r["risk_level"]] += 1

            export_data = {
                "meta": {
                    "target":      self.target,
                    "exported_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "total":       len(results),
                    "critical":    level_counts[CRITICAL],
                    "high":        level_counts[HIGH],
                    "medium":      level_counts[MEDIUM],
                    "low":         level_counts[LOW],
                    "info":        level_counts[INFO],
                    "tool":        "Cyber Attack Surface Assessment Framework",
                },
                "findings": results,
            }

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, default=str)

            print(f"{GREEN}[+] Risk data exported → {filepath}{RESET}")
            return filepath

        except OSError as e:
            print(f"{RED}[-] Failed to export JSON: {e}{RESET}")
            return None

    def display_results(self, results: List[Dict]) -> None:
        """Prints a colour-coded risk analysis table followed by a per-level summary."""
        if not results:
            print(f"{RED}[-] No risk analysis results to display{RESET}")
            return

        print(f"{BOLD}{GREEN}[+] Risk Analysis — {self.target}{RESET}\n")
        print(f"  {CYAN}{'PORT':<12}{'SERVICE':<12}{'RISK LEVEL':<12}REASON{RESET}")
        print(f"  {BLUE}{'─' * 72}{RESET}")

        for r in results:
            port_str = f"{r['port']}/{r['protocol']}"
            level    = r["risk_level"]
            colour   = RISK_COLOURS.get(level, RESET)
            reason   = r["risk_reason"][:55]

            print(
                f"  {GREEN}{port_str:<12}{RESET}"
                f"{CYAN}{r['service']:<12}{RESET}"
                f"{colour}{level:<12}{RESET}"
                f"{reason}"
            )

        level_counts = {lvl: 0 for lvl in [CRITICAL, HIGH, MEDIUM, LOW, INFO]}
        for r in results:
            level_counts[r["risk_level"]] += 1

        print(f"\n  {BOLD}{CYAN}── Risk Summary ─────────────────────────{RESET}")
        for level in [CRITICAL, HIGH, MEDIUM, LOW, INFO]:
            count  = level_counts[level]
            colour = RISK_COLOURS.get(level, RESET)
            bar    = "█" * count
            print(f"  {colour}{level:<10}{RESET}  {count:>2}  {colour}{bar}{RESET}")

        print()
