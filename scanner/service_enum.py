import socket
import ssl
import json
import os
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Optional

GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

CONFIDENCE_HIGH   = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW    = "LOW"

# Probes to send after connecting — services that speak first get None
SERVICE_PROBES: Dict[str, Optional[bytes]] = {
    "http":     f"HEAD / HTTP/1.0\r\nHost: {self.target}\r\n\r\n".encode()",
    "https":    f"HEAD / HTTP/1.0\r\nHost: {self.target}\r\n\r\n".encode(),
    "http-alt": f"HEAD / HTTP/1.0\r\nHost: {self.target}\r\n\r\n".encode(),
    "ftp":      None,   # sends banner on connect
    "ssh":      None,
    "smtp":     None,
    "pop3":     None,
    "imap":     None,
    "mysql":    None,
    "rdp":      None,   # no text banner, but connection confirms it's there
}

# Ports that need SSL/TLS wrapping
SSL_PORTS = {443, 8443, 993, 995, 465, 636, 989, 990}

# Services worth flagging in the report — maps to a short human-readable note
RISKY_SERVICES: Dict[str, str] = {
    "ftp":    "Unencrypted protocol — credentials transmitted in plain text",
    "telnet": "Unencrypted protocol — all traffic visible to network sniffers",
    "smtp":   "Mail server — verify it is not configured as an open relay",
    "pop3":   "Unencrypted mail retrieval — credentials sent in plain text",
    "mysql":  "Database port exposed — verify it is not internet-facing",
    "mssql":  "Database port exposed — verify it is not internet-facing",
    "vnc":    "Remote desktop service — check for weak or missing authentication",
    "rdp":    "Remote desktop service — high-value target, check patch level",
    "smb":    "File sharing protocol — check for EternalBlue (MS17-010)",
    "snmp":   "Network management — check for default community strings",
    "ldap":   "Directory service — check for anonymous bind vulnerability",
}


class ServiceEnumerator:
    """
    Grabs service banners from open ports and enriches each finding.

    Each result gets a banner, parsed version, confidence level, and a risk
    flag if the service is known to be commonly misconfigured. Uses a thread
    pool so all connections happen in parallel rather than sequentially.
    """

    def __init__(self, target: str, timeout: int = 3, max_workers: int = 10, output_dir: str = "scans"):
        self.target      = target
        self.timeout     = timeout
        self.max_workers = max_workers
        self.output_dir  = output_dir

    def _should_use_ssl(self, port: int, service: str) -> bool:
        """True if this port/service is expected to use TLS."""
        return port in SSL_PORTS or service in ("https", "imaps", "pop3s", "smtps")

    def _grab_banner_ssl(self, port: int, probe: Optional[bytes]) -> str:
        """SSL banner grab. We disable cert verification intentionally — we're assessing, not validating."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(self.timeout)

        with ctx.wrap_socket(raw, server_hostname=self.target) as sock:
            sock.connect((self.target, port))
            if probe:
                sock.sendall(probe)
            return sock.recv(2048).decode("utf-8", errors="ignore").strip()

    def _grab_banner_plain(self, port: int, probe: Optional[bytes]) -> str:
        """Plain TCP banner grab."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            if probe:
                sock.sendall(probe)
            return sock.recv(2048).decode("utf-8", errors="ignore").strip()

    def _grab_banner(self, port: int, service: str) -> str:
        """
        Connects to a port and grabs whatever the service says first.
        Tries SSL first on likely-encrypted ports, falls back to plain TCP.
        Returns empty string if the port doesn't respond.
        """
        probe = SERVICE_PROBES.get(service, b"\r\n")

        try:
            if self._should_use_ssl(port, service):
                try:
                    return self._grab_banner_ssl(port, probe)
                except ssl.SSLError:
                    # Might just be plain TCP pretending to be HTTPS
                    return self._grab_banner_plain(port, probe)

            return self._grab_banner_plain(port, probe)

        except (socket.timeout, ConnectionRefusedError, OSError):
            return ""
        except Exception:
            # Never let one unresponsive port crash the whole enumeration
            return ""

    def _clean_banner(self, raw_banner: str) -> str:
        """Extracts the first useful line from a raw banner, capped at 120 chars."""
        if not raw_banner:
            return "—"
        for line in raw_banner.splitlines():
            line = line.strip()
            if line:
                return line[:120]
        return "—"

    def _parse_version(self, banner: str, nmap_version: str) -> str:
        """Prefers the Nmap-detected version, falls back to the raw banner."""
        if nmap_version and nmap_version != "—":
            return nmap_version
        if banner and banner != "—":
            return banner
        return "Unknown"

    def _assign_confidence(self, banner: str, nmap_version: str) -> str:
        """
        HIGH   = we have both a banner and a confirmed version
        MEDIUM = we have one or the other
        LOW    = nothing — just an open port with no identifying info
        """
        has_banner  = banner not in ("—", "", "Unknown")
        has_version = nmap_version not in ("—", "", "Unknown")

        if has_banner and has_version:
            return CONFIDENCE_HIGH
        if has_banner or has_version:
            return CONFIDENCE_MEDIUM
        return CONFIDENCE_LOW

    def _enumerate_single(self, port_info: Dict) -> Dict:
        """Enumerates a single port — this is what the thread pool calls."""
        port         = port_info["port"]
        service      = port_info.get("service", "unknown")
        nmap_version = port_info.get("version", "—")

        raw_banner   = self._grab_banner(port, service)
        clean_banner = self._clean_banner(raw_banner)
        version      = self._parse_version(clean_banner, nmap_version)
        confidence   = self._assign_confidence(clean_banner, nmap_version)
        risk_note    = RISKY_SERVICES.get(service, "")

        return {
            **port_info,
            "banner":       clean_banner,
            "version":      version,
            "confidence":   confidence,
            "risk_note":    risk_note,
            "flagged":      bool(risk_note),
            "enumerated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def enumerate(self, ports: List[Dict]) -> List[Dict]:
        """
        Enumerates all open ports in parallel and returns enriched results.

        Args:
            ports: List of port dicts from PortScanner.run_scan()

        Returns:
            List of enriched dicts sorted by port number.
        """
        if not ports:
            print(f"{RED}[-] No ports provided to enumerate{RESET}")
            return []

        start_time = datetime.now()
        print(f"{YELLOW}[*] Enumerating {len(ports)} service(s) on "
              f"{self.target} — started at {start_time.strftime('%H:%M:%S')}{RESET}\n")

        results = []
        errors = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_map = {executor.submit(self._enumerate_single, p): p for p in ports}

            for future in concurrent.futures.as_completed(future_map):
                try:
                    results.append(future.result())
                except Exception as e:
                    errors += 1
                    port_info = future_map[future]
                    print(f"{RED}[-] Error on port {port_info.get('port', '?')}: {e}{RESET}")

        duration = round((datetime.now() - start_time).total_seconds(), 2)

        for r in results:
            r["scan_duration_seconds"] = duration

        if errors:
            print(f"{YELLOW}[!] {errors} port(s) could not be enumerated{RESET}")

        print(f"{CYAN}[*] Enumeration completed in {duration}s{RESET}\n")

        return sorted(results, key=lambda x: x["port"])

    def export_json(self, results: List[Dict]) -> Optional[str]:
        """Saves enumeration results to a timestamped JSON file in scans/."""
        if not results:
            print(f"{YELLOW}[!] No results to export{RESET}")
            return None

        try:
            os.makedirs(self.output_dir, exist_ok=True)

            timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_target = self.target.replace(".", "_")
            filename    = f"{safe_target}_services_{timestamp}.json"
            filepath    = os.path.join(self.output_dir, filename)

            export_data = {
                "meta": {
                    "target":         self.target,
                    "exported_at":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "total_services": len(results),
                    "flagged_count":  sum(1 for r in results if r["flagged"]),
                    "tool":           "Cyber Attack Surface Assessment Framework",
                },
                "services": results,
            }

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, default=str)

            print(f"{GREEN}[+] Results exported → {filepath}{RESET}")
            return filepath

        except OSError as e:
            print(f"{RED}[-] Failed to export JSON: {e}{RESET}")
            return None

    def display_results(self, results: List[Dict]) -> None:
        """Prints a formatted service enumeration table with risk flags."""
        if not results:
            print(f"{RED}[-] No enumeration results to display{RESET}")
            return

        flagged   = [r for r in results if r["flagged"]]
        high_conf = [r for r in results if r["confidence"] == CONFIDENCE_HIGH]
        low_conf  = [r for r in results if r["confidence"] == CONFIDENCE_LOW]

        print(f"{BOLD}{GREEN}[+] Service Enumeration Results — {self.target}{RESET}\n")
        print(f"  {CYAN}{'PORT':<12}{'SERVICE':<12}{'VERSION / BANNER':<40}{'CONFIDENCE':<12}FLAG{RESET}")
        print(f"  {BLUE}{'─' * 78}{RESET}")

        for r in results:
            port_str = f"{r['port']}/{r['protocol']}"
            version  = r["version"][:38] if len(r["version"]) > 38 else r["version"]
            flag_str = f"{RED}⚠  RISK{RESET}" if r["flagged"] else f"{GREEN}OK{RESET}"

            conf = r["confidence"]
            if conf == CONFIDENCE_HIGH:
                conf_str = f"{GREEN}{conf}{RESET}"
            elif conf == CONFIDENCE_MEDIUM:
                conf_str = f"{YELLOW}{conf}{RESET}"
            else:
                conf_str = f"{RED}{conf}{RESET}"

            print(
                f"  {GREEN}{port_str:<12}{RESET}"
                f"{CYAN}{r['service']:<12}{RESET}"
                f"{version:<40}"
                f"{conf_str:<20}"
                f"{flag_str}"
            )

        if flagged:
            print(f"\n  {BOLD}{RED}⚠  Risky Services Detected{RESET}")
            print(f"  {BLUE}{'─' * 78}{RESET}")
            for r in flagged:
                port_str = f"{r['port']}/{r['protocol']}"
                print(f"  {RED}{port_str:<12}{RESET}{YELLOW}{r['service']:<14}{RESET}{r['risk_note']}")

        print(f"\n  {BOLD}{CYAN}── Enumeration Summary ──────────────────{RESET}")
        print(f"  Total services   : {len(results)}")
        print(f"  Flagged (risky)  : {RED}{len(flagged)}{RESET}")
        print(f"  High confidence  : {GREEN}{len(high_conf)}{RESET}")
        print(f"  Low confidence   : {YELLOW}{len(low_conf)}{RESET}")
        print(f"  Timestamp        : {results[0].get('enumerated_at', 'N/A') if results else 'N/A'}")
        print()
