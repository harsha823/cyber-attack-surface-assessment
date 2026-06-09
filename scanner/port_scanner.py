import subprocess
import xml.etree.ElementTree as ET
import os
import shutil
from datetime import datetime

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
RESET  = "\033[0m"

# Nmap timing templates — T2 is quieter, T4 is faster
SPEED_PROFILES = {
    "sneaky": "-T2",
    "normal": "-T3",
    "fast":   "-T4",
}


class PortScanner:
    """
    Runs an Nmap service scan and parses the results.

    Saves the raw XML output to the scans/ folder so you have a record,
    then returns a clean list of open port dicts for the next phase.
    """

    def __init__(self, target: str, ports: str = "1-1024", speed: str = "normal", scan_dir: str = "scans"):
        """
        Args:
            target   : IP address or hostname to scan
            ports    : Port range, e.g. "1-1024", "1-65535", or "22,80,443"
            speed    : "sneaky", "normal", or "fast"
            scan_dir : Where to save the raw Nmap XML output
        """
        self.target   = target
        self.ports    = ports
        self.speed    = SPEED_PROFILES.get(speed, "-T3")
        self.scan_dir = scan_dir

    def _check_nmap(self) -> bool:
        """Returns False (with a helpful message) if nmap isn't installed."""
        if shutil.which("nmap") is None:
            print(f"{RED}[-] Nmap not found. Install it:{RESET}")
            print(f"    Linux  : sudo apt install nmap")
            print(f"    macOS  : brew install nmap")
            print(f"    Windows: https://nmap.org/download.html")
            return False
        return True

    def _get_output_path(self) -> str:
        """Builds a timestamped path for saving scan output, e.g. scans/192_168_56_5_20240601_143022"""
        os.makedirs(self.scan_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.target.replace('.', '_')}_{timestamp}"
        return os.path.join(self.scan_dir, filename)

    def _build_command(self, output_path: str) -> list:
        """
        Builds the Nmap command.
        -sV detects versions, --open skips closed ports, -oX saves XML for parsing.
        """
        return [
            "nmap", "-sV", "--open",
            "-p", self.ports,
            self.speed,
            "-oX", f"{output_path}.xml",
            self.target,
        ]

    def _parse_xml(self, xml_path: str) -> list:
        """
        Parses Nmap XML into a list of open port dicts.

        Returns a list like:
            [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.2"}, ...]
        """
        if not os.path.exists(xml_path):
            print(f"{RED}[-] XML output file not found: {xml_path}{RESET}")
            return []

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except ET.ParseError as e:
            print(f"{RED}[-] Failed to parse Nmap XML: {e}{RESET}")
            return []

        open_ports = []

        for host in root.findall("host"):
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port in ports_elem.findall("port"):
                state_elem   = port.find("state")
                service_elem = port.find("service")

                if state_elem is None or state_elem.get("state") != "open":
                    continue

                # Build version string by concatenating whatever nmap found
                version = ""
                if service_elem is not None:
                    parts = [
                        service_elem.get("product", ""),
                        service_elem.get("version", ""),
                        service_elem.get("extrainfo", ""),
                    ]
                    version = " ".join(p for p in parts if p)

                open_ports.append({
                    "port":     int(port.get("portid", 0)),
                    "protocol": port.get("protocol", "tcp"),
                    "state":    "open",
                    "service":  service_elem.get("name", "unknown") if service_elem is not None else "unknown",
                    "version":  version or "—",
                })

        return sorted(open_ports, key=lambda x: x["port"])

    def run_scan(self) -> list:
        """
        Runs the Nmap scan and returns parsed results.

        Returns an empty list if nmap isn't installed, the scan fails,
        or the target has no open ports in the given range.
        """
        if not self._check_nmap():
            return []

        output_path = self._get_output_path()
        command = self._build_command(output_path)

        print(f"{YELLOW}[*] Running: {' '.join(command)}{RESET}\n")

        try:
            subprocess.run(command, check=True, timeout=300)
        except subprocess.CalledProcessError as e:
            print(f"{RED}[-] Nmap exited with error code {e.returncode}{RESET}")
            return []
        except subprocess.TimeoutExpired:
            print(f"{RED}[-] Scan timed out after 5 minutes{RESET}")
            return []
        except Exception as e:
            print(f"{RED}[-] Unexpected error during scan: {e}{RESET}")
            return []

        xml_path = f"{output_path}.xml"
        print(f"\n{CYAN}[*] Raw output saved → {xml_path}{RESET}")

        return self._parse_xml(xml_path)

    def display_results(self, results: list) -> None:
        """Prints a formatted table of open ports."""
        if not results:
            print(f"{RED}[-] No open ports found{RESET}")
            return

        print(f"\n{GREEN}[+] {len(results)} open port(s) found on {self.target}{RESET}\n")
        print(f"  {CYAN}{'PORT':<12}{'PROTOCOL':<10}{'STATE':<8}{'SERVICE':<14}{'VERSION'}{RESET}")
        print(f"  {BLUE}{'─' * 60}{RESET}")

        for entry in results:
            port = f"{entry['port']}/{entry['protocol']}"
            print(
                f"  {GREEN}{port:<12}{RESET}"
                f"{YELLOW}{entry['protocol']:<10}{RESET}"
                f"{GREEN}{entry['state']:<8}{RESET}"
                f"{CYAN}{entry['service']:<14}{RESET}"
                f"{entry['version']}"
            )

        print()
