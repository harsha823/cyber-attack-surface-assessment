"""
service_enum.py
---------------
Phase 3 — Service Enumeration

Takes the open ports discovered in Phase 2 and probes each one to:
  - Grab the service banner
  - Identify service name and version
  - Flag risky or misconfigured services
  - Assign a confidence level to each result
  - Export findings to JSON for use in later phases

Usage:
    from scanner.service_enum import ServiceEnumerator

    se      = ServiceEnumerator(target="192.168.56.101")
    results = se.enumerate(ports)
    se.display_results(results)
    se.export_json(results)

Author : Cyber Attack Surface Assessment Framework
"""

import socket
import ssl
import json
import os
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Optional


# ── Terminal colours (ANSI — no external libraries required) ───────────
GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

# ── Confidence levels ──────────────────────────────────────────────────
# HIGH   = banner clearly identifies service + version
# MEDIUM = banner received but version not confirmed
# LOW    = no banner — result based on Nmap port/service guess only
CONFIDENCE_HIGH   = "HIGH"
CONFIDENCE_MEDIUM = "MEDIUM"
CONFIDENCE_LOW    = "LOW"

# ── Service probes ─────────────────────────────────────────────────────
# Sent immediately after connecting to trigger a banner response.
# None = service sends banner on connect without a probe.
SERVICE_PROBES: Dict[str, Optional[bytes]] = {
    "http"    : b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    "https"   : b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    "http-alt": b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    "ftp"     : None,   # sends banner on connect
    "ssh"     : None,   # sends banner on connect
    "smtp"    : None,   # sends banner on connect
    "pop3"    : None,   # sends banner on connect
    "imap"    : None,   # sends banner on connect
    "mysql"   : None,   # sends banner on connect
    "rdp"     : None,   # no text banner — connection itself confirms presence
}

# ── SSL/TLS port list ──────────────────────────────────────────────────
# These ports use encrypted connections — we wrap with SSL before reading.
SSL_PORTS = {443, 8443, 993, 995, 465, 636, 989, 990}

# ── Risky service definitions ──────────────────────────────────────────
# Maps service name → plain-English risk description.
# Used to auto-flag findings that need attention in the report.
RISKY_SERVICES: Dict[str, str] = {
    "ftp"     : "Unencrypted protocol — credentials transmitted in plain text",
    "telnet"  : "Unencrypted protocol — all traffic visible to network sniffers",
    "smtp"    : "Mail server — verify it is not configured as an open relay",
    "pop3"    : "Unencrypted mail retrieval — credentials sent in plain text",
    "mysql"   : "Database port exposed — verify it is not internet-facing",
    "mssql"   : "Database port exposed — verify it is not internet-facing",
    "vnc"     : "Remote desktop service — check for weak or missing authentication",
    "rdp"     : "Remote desktop service — high-value target, check patch level",
    "smb"     : "File sharing protocol — check for EternalBlue (MS17-010)",
    "snmp"    : "Network management — check for default community strings",
    "ldap"    : "Directory service — check for anonymous bind vulnerability",
}


class ServiceEnumerator:
    """
    Grabs banners from open ports to identify running services and versions.

    Each result is enriched with:
        - Raw banner text from the service
        - Parsed version string (where detectable)
        - Confidence level (HIGH / MEDIUM / LOW)
        - Risk flag and description (for known risky services)
        - Enumeration timestamp

    Results can be displayed in the terminal or exported to JSON
    for use by Phase 4 (risk_analyzer.py).

    Example:
        se      = ServiceEnumerator(target="192.168.56.101")
        results = se.enumerate(open_ports)
        se.display_results(results)
        se.export_json(results)
    """

    def __init__(
        self,
        target      : str,
        timeout     : int = 3,
        max_workers : int = 10,
        output_dir  : str = "scans",
    ) -> None:
        """
        Initialises the ServiceEnumerator.

        Args:
            target      : IP address or hostname to enumerate.
            timeout     : Seconds to wait per connection attempt. Default: 3.
            max_workers : Maximum parallel banner grabs. Default: 10.
            output_dir  : Directory to save JSON export files. Default: scans/.
        """
        self.target      = target
        self.timeout     = timeout
        self.max_workers = max_workers
        self.output_dir  = output_dir

    # ──────────────────────────────────────────────────────────────────
    # Private — banner grabbing
    # ──────────────────────────────────────────────────────────────────

    def _should_use_ssl(self, port: int, service: str) -> bool:
        """
        Decides whether to attempt an SSL/TLS connection.

        Returns True if the port is in the known SSL list
        or the service name suggests encryption.

        Args:
            port    : TCP port number.
            service : Service name hint from Nmap.

        Returns:
            True if SSL should be attempted first.
        """
        return port in SSL_PORTS or service in ("https", "imaps", "pop3s", "smtps")

    def _grab_banner_ssl(self, port: int, probe: Optional[bytes]) -> str:
        """
        Attempts an SSL/TLS banner grab on the specified port.

        Disables certificate verification intentionally — we are
        assessing the service, not validating its certificate chain.

        Args:
            port  : TCP port to connect to.
            probe : Bytes to send after connecting, or None.

        Returns:
            Decoded banner string, or empty string on failure.

        Raises:
            ssl.SSLError : Caller catches this and falls back to plain TCP.
        """
        ctx                = ssl.create_default_context()
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
        """
        Plain TCP banner grab — used directly or as SSL fallback.

        Args:
            port  : TCP port to connect to.
            probe : Bytes to send after connecting, or None.

        Returns:
            Decoded banner string, or empty string on failure.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect((self.target, port))
            if probe:
                sock.sendall(probe)
            return sock.recv(2048).decode("utf-8", errors="ignore").strip()

    def _grab_banner(self, port: int, service: str) -> str:
        """
        Grabs the service banner from an open port.

        Tries SSL first if the port/service suggests encryption,
        then falls back to plain TCP if SSL fails.

        Args:
            port    : TCP port to connect to.
            service : Service name hint from Nmap (e.g. "http", "ssh").

        Returns:
            Raw banner string, or empty string if nothing received.
        """
        # Get the right probe for this service, default to a blank line
        probe = SERVICE_PROBES.get(service, b"\r\n")

        try:
            if self._should_use_ssl(port, service):
                try:
                    return self._grab_banner_ssl(port, probe)
                except ssl.SSLError:
                    # SSL handshake failed — service may not actually use TLS
                    return self._grab_banner_plain(port, probe)

            return self._grab_banner_plain(port, probe)

        except (socket.timeout, ConnectionRefusedError, OSError):
            # Host did not respond in time or actively refused — not an error
            return ""

        except Exception:
            # Catch-all — never let one port crash the whole enumeration
            return ""

    # ──────────────────────────────────────────────────────────────────
    # Private — result enrichment
    # ──────────────────────────────────────────────────────────────────

    def _clean_banner(self, raw_banner: str) -> str:
        """
        Extracts the first meaningful line from a raw banner string.

        Strips control characters, limits to 120 characters,
        and falls back to an em dash if nothing useful is found.

        Args:
            raw_banner : Full raw banner string from _grab_banner().

        Returns:
            Cleaned single-line string, or "—" if empty.
        """
        if not raw_banner:
            return "—"

        # Take first non-empty line
        for line in raw_banner.splitlines():
            line = line.strip()
            if line:
                return line[:120]

        return "—"

    def _parse_version(self, banner: str, nmap_version: str) -> str:
        """
        Returns the best available version string.

        Prefers the Nmap-detected version from Phase 2 if present,
        otherwise falls back to the raw banner text.

        Args:
            banner       : Cleaned banner string from _clean_banner().
            nmap_version : Version string already detected by Nmap (may be "—").

        Returns:
            Version string, or "Unknown" if neither source has data.
        """
        if nmap_version and nmap_version != "—":
            return nmap_version
        if banner and banner != "—":
            return banner
        return "Unknown"

    def _assign_confidence(self, banner: str, nmap_version: str) -> str:
        """
        Assigns a confidence level to the enumeration result.

        HIGH   = Nmap version confirmed AND we grabbed a banner
        MEDIUM = Either Nmap version OR banner (not both)
        LOW    = Neither — result is based only on the open port itself

        Args:
            banner       : Cleaned banner string.
            nmap_version : Version string from Nmap Phase 2 results.

        Returns:
            One of: CONFIDENCE_HIGH, CONFIDENCE_MEDIUM, CONFIDENCE_LOW
        """
        has_banner  = banner not in ("—", "", "Unknown")
        has_version = nmap_version not in ("—", "", "Unknown")

        if has_banner and has_version:
            return CONFIDENCE_HIGH
        if has_banner or has_version:
            return CONFIDENCE_MEDIUM
        return CONFIDENCE_LOW

    def _enumerate_single(self, port_info: Dict) -> Dict:
        """
        Enumerates one port and returns a fully enriched result dict.

        This is the method submitted to the thread pool — one call
        per open port, all running in parallel.

        Args:
            port_info : Single port dict from PortScanner.run_scan().
                        Expected keys: port, protocol, state, service, version

        Returns:
            Enriched dict with banner, version, confidence, risk, and timestamp.
        """
        port         = port_info["port"]
        service      = port_info.get("service", "unknown")
        nmap_version = port_info.get("version", "—")

        # Record when this specific port was enumerated
        enum_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Grab the raw banner from the live service
        raw_banner   = self._grab_banner(port, service)
        clean_banner = self._clean_banner(raw_banner)
        version      = self._parse_version(clean_banner, nmap_version)
        confidence   = self._assign_confidence(clean_banner, nmap_version)
        risk_note    = RISKY_SERVICES.get(service, "")

        return {
            # ── Carry forward all Phase 2 fields ──────────────────────
            **port_info,

            # ── New Phase 3 fields ─────────────────────────────────────
            "banner"     : clean_banner,
            "version"    : version,
            "confidence" : confidence,
            "risk_note"  : risk_note,
            "flagged"    : bool(risk_note),
            "enumerated_at": enum_time,
        }

    # ──────────────────────────────────────────────────────────────────
    # Public — main interface
    # ──────────────────────────────────────────────────────────────────

    def enumerate(self, ports: List[Dict]) -> List[Dict]:
        """
        Enumerates all open ports in parallel and returns enriched results.

        Uses a thread pool so all banner grabs run simultaneously
        rather than waiting for each one to time out sequentially.

        Args:
            ports : List of port dicts from PortScanner.run_scan().

        Returns:
            List of enriched result dicts, sorted by port number.
            Returns empty list if input is empty or all grabs fail.
        """
        if not ports:
            print(f"{RED}[-] No ports provided to enumerate{RESET}")
            return []

        start_time = datetime.now()
        print(f"{YELLOW}[*] Enumerating {len(ports)} service(s) on "
              f"{self.target} — started at {start_time.strftime('%H:%M:%S')}{RESET}\n")

        results: List[Dict] = []
        errors  : int       = 0

        # Submit all ports to the thread pool simultaneously
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:

            future_map = {
                executor.submit(self._enumerate_single, p): p
                for p in ports
            }

            for future in concurrent.futures.as_completed(future_map):
                try:
                    results.append(future.result())
                except Exception as e:
                    errors += 1
                    port_info = future_map[future]
                    print(f"{RED}[-] Error enumerating port "
                          f"{port_info.get('port', '?')}: {e}{RESET}")

        end_time  = datetime.now()
        duration  = round((end_time - start_time).total_seconds(), 2)

        # Attach summary metadata to each result for the JSON export
        for r in results:
            r["scan_duration_seconds"] = duration

        if errors:
            print(f"{YELLOW}[!] {errors} port(s) could not be enumerated{RESET}")

        print(f"{CYAN}[*] Enumeration completed in {duration}s{RESET}\n")

        return sorted(results, key=lambda x: x["port"])

    def export_json(self, results: List[Dict]) -> Optional[str]:
        """
        Exports enumeration results to a timestamped JSON file.

        The JSON file is saved to self.output_dir and is consumed
        by Phase 4 (risk_analyzer.py) to perform risk scoring.

        File naming: <target>_services_<YYYYMMDD_HHMMSS>.json
        Example    : scans/192.168.56.101_services_20240601_143022.json

        Args:
            results : List of enriched dicts from enumerate().

        Returns:
            Path to the saved JSON file, or None if export failed.
        """
        if not results:
            print(f"{YELLOW}[!] No results to export{RESET}")
            return None

        try:
            os.makedirs(self.output_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_target = self.target.replace(".", "_")
            filename    = f"{safe_target}_services_{timestamp}.json"
            filepath    = os.path.join(self.output_dir, filename)

            # Build the export structure
            export_data = {
                "meta": {
                    "target"        : self.target,
                    "exported_at"   : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "total_services": len(results),
                    "flagged_count" : sum(1 for r in results if r["flagged"]),
                    "tool"          : "Cyber Attack Surface Assessment Framework",
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
        """
        Prints a formatted, colour-coded service enumeration table.

        Sections:
            1. Full service table with banner and confidence level
            2. Risky service warnings (if any flagged)
            3. Enumeration statistics summary

        Args:
            results : List of enriched dicts from enumerate().
        """
        if not results:
            print(f"{RED}[-] No enumeration results to display{RESET}")
            return

        flagged  = [r for r in results if r["flagged"]]
        high_conf = [r for r in results if r["confidence"] == CONFIDENCE_HIGH]
        low_conf  = [r for r in results if r["confidence"] == CONFIDENCE_LOW]

        # ── Section 1: Service table ───────────────────────────────────
        print(f"{BOLD}{GREEN}[+] Service Enumeration Results — "
              f"{self.target}{RESET}\n")

        header = (
            f"  {CYAN}{'PORT':<12}"
            f"{'SERVICE':<12}"
            f"{'VERSION / BANNER':<40}"
            f"{'CONFIDENCE':<12}"
            f"FLAG{RESET}"
        )
        print(header)
        print(f"  {BLUE}{'─' * 78}{RESET}")

        for r in results:
            port_str   = f"{r['port']}/{r['protocol']}"
            version    = r["version"][:38] if len(r["version"]) > 38 else r["version"]
            flag_str   = f"{RED}⚠  RISK{RESET}" if r["flagged"] else f"{GREEN}OK{RESET}"

            # Colour-code confidence level
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

        # ── Section 2: Risky service warnings ─────────────────────────
        if flagged:
            print(f"\n  {BOLD}{RED}⚠  Risky Services Detected{RESET}")
            print(f"  {BLUE}{'─' * 78}{RESET}")

            for r in flagged:
                port_str = f"{r['port']}/{r['protocol']}"
                print(
                    f"  {RED}{port_str:<12}{RESET}"
                    f"{YELLOW}{r['service']:<14}{RESET}"
                    f"{r['risk_note']}"
                )

        # ── Section 3: Enumeration statistics ─────────────────────────
        print(f"\n  {BOLD}{CYAN}── Enumeration Summary ──────────────────{RESET}")
        print(f"  Total services   : {len(results)}")
        print(f"  Flagged (risky)  : {RED}{len(flagged)}{RESET}")
        print(f"  High confidence  : {GREEN}{len(high_conf)}{RESET}")
        print(f"  Low confidence   : {YELLOW}{len(low_conf)}{RESET}")
        print(f"  Timestamp        : "
              f"{results[0].get('enumerated_at', 'N/A') if results else 'N/A'}")
        print()
