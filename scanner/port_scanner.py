
import subprocess
import xml.etree.ElementTree as ET
import os
import shutil
from datetime import datetime
from utils.colors import GREEN, RED, YELLOW, CYAN, BLUE, RESET

SPEED_PROFILES = {
    "sneaky" : "-T2",   
    "normal" : "-T3",   
    "fast"   : "-T4",   
}


class PortScanner:
    """
    Wraps Nmap to perform a TCP port scan and return structured results.

    Features:
        - Checks Nmap is installed before running
        - Saves raw XML output to scans/ directory
        - Parses XML into clean list of dicts
        - Colour-coded terminal output
        - Configurable port range and scan speed
    """

    def __init__(
        self,
        target   : str,
        ports    : str = "1-1024",
        speed    : str = "normal",
        scan_dir : str = "scans",
    ):
        """
        Args:
            target   : IP address or hostname to scan
            ports    : Port range (e.g. "1-1024", "1-65535", "22,80,443")
            speed    : "sneaky", "normal", or "fast"  (default: "normal")
            scan_dir : Directory to save raw Nmap XML output
        """
        self.target   = target
        self.ports    = ports
        self.speed    = SPEED_PROFILES.get(speed, "-T3")
        self.scan_dir = scan_dir

   

    def _check_nmap(self) -> bool:
        """
        Verifies that Nmap is installed and accessible on PATH.

        Returns:
            True if nmap found, False otherwise
        """
        if shutil.which("nmap") is None:
            print(f"{RED}[-] Nmap not found. Install it first:{RESET}")
            print(f"    Linux  : sudo apt install nmap")
            print(f"    macOS  : brew install nmap")
            print(f"    Windows: https://nmap.org/download.html")
            return False
        return True

    def _get_output_path(self) -> str:
        """
        Builds a timestamped file path for saving scan output.

        Example: scans/192.168.56.101_20240601_143022
        """
        os.makedirs(self.scan_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename  = f"{self.target.replace('.', '_')}_{timestamp}"
        return os.path.join(self.scan_dir, filename)

    def _build_command(self, output_path: str) -> list:
        """
        Builds the Nmap command.

        Flags used:
            -sV          : probe open ports to detect service/version
            -p           : port range
            -T<n>        : timing template (speed)
            --open       : only show open ports (cleaner output)
            -oX          : save output as XML for parsing
        """
        return [
            "nmap",
            "-sV",
            "--open",
            "-p", self.ports,
            self.speed,
            "-oX", f"{output_path}.xml",
            self.target,
        ]

    def _parse_xml(self, xml_path: str) -> list:
        """
        Parses Nmap XML output into a clean list of open port dicts.

        Args:
            xml_path : path to the .xml file Nmap created

        Returns:
            List of dicts, one per open port:
            [
                {
                    "port"    : 22,
                    "protocol": "tcp",
                    "state"   : "open",
                    "service" : "ssh",
                    "version" : "OpenSSH 8.2",
                },
                ...
            ]
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

                if state_elem is None:
                    continue

                state = state_elem.get("state", "")
                if state != "open":
                    continue

                # Build version string from available fields
                version = ""
                if service_elem is not None:
                    product      = service_elem.get("product",      "")
                    ver          = service_elem.get("version",       "")
                    extra        = service_elem.get("extrainfo",     "")
                    version_parts = [p for p in [product, ver, extra] if p]
                    version       = " ".join(version_parts)

                open_ports.append({
                    "port"    : int(port.get("portid", 0)),
                    "protocol": port.get("protocol", "tcp"),
                    "state"   : state,
                    "service" : service_elem.get("name", "unknown") if service_elem is not None else "unknown",
                    "version" : version or "—",
                })

        return sorted(open_ports, key=lambda x: x["port"])

   
    def run_scan(self) -> list:
        """
        Runs the Nmap scan and returns parsed results.

        Steps:
            1. Check Nmap is installed
            2. Build command
            3. Run via subprocess
            4. Parse XML output
            5. Return list of open port dicts

        Returns:
            List of open port dicts (see _parse_xml for structure)
            Empty list on failure
        """
        if not self._check_nmap():
            return []

        output_path = self._get_output_path()
        command     = self._build_command(output_path)

        print(f"{YELLOW}[*] Running: {' '.join(command)}{RESET}\n")

        try:
            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,  
                stderr=subprocess.PIPE,      
                timeout=300,                 
                text=True,
            )

            if result.returncode != 0:
                print(f"{RED}[-] Nmap exited with error code {result.returncode}{RESET}")
                if result.stderr:
                    print(f"{RED}{result.stderr.strip()}{RESET}")
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
        """
        Prints a formatted table of open ports.

        Args:
            results : list returned by run_scan()
        """
        if not results:
            print(f"{RED}[-] No open ports found{RESET}")
            return

        count = len(results)
        print(f"\n{GREEN}[+] {count} open port(s) found on {self.target}{RESET}\n")

        # Column headers
        print(f"  {CYAN}{'PORT':<12}{'PROTOCOL':<10}{'STATE':<8}{'SERVICE':<14}{'VERSION'}{RESET}")
        print(f"  {BLUE}{'─'*60}{RESET}")

        for entry in results:
            port     = f"{entry['port']}/{entry['protocol']}"
            state    = entry["state"]
            service  = entry["service"]
            version  = entry["version"]

            print(
                f"  {GREEN}{port:<12}{RESET}"
                f"{YELLOW}{entry['protocol']:<10}{RESET}"
                f"{GREEN}{state:<8}{RESET}"
                f"{CYAN}{service:<14}{RESET}"
                f"{version}"
            )

        print()
