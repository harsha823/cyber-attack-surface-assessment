import subprocess
import xml.etree.ElementTree as ET
import os
import shutil
from datetime import datetime
from utils.colors import GREEN, RED, YELLOW, CYAN, BLUE, RESET

SPEED = {"sneaky": "-T2", "normal": "-T3", "fast": "-T4"}


class PortScanner:
    def __init__(self, target, ports="1-1024", speed="normal", scan_dir="scans"):
        self.target   = target
        self.ports    = ports
        self.speed    = SPEED.get(speed, "-T3")
        self.scan_dir = scan_dir

    def run_scan(self):
        if not shutil.which("nmap"):
            print(f"{RED}[-] nmap not found — install it (apt/brew/nmap.org){RESET}")
            return []

        os.makedirs(self.scan_dir, exist_ok=True)
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_base = os.path.join(self.scan_dir, f"{self.target.replace('.', '_')}_{ts}")
        xml_path = f"{out_base}.xml"

        cmd = ["nmap", "-sV", "--open", "-p", self.ports, self.speed, "-oX", xml_path, self.target]
        print(f"{YELLOW}[*] {' '.join(cmd)}{RESET}\n")

        # scale timeout with port range so wide scans don't get killed early
        try:
            lo, hi = (int(x) for x in self.ports.split("-"))
            timeout = max(120, min((hi - lo) // 2, 1800))
        except ValueError:
            timeout = 300  # comma list or single port, just give it 5 min

        try:
            subprocess.run(cmd, check=True, timeout=timeout)
        except subprocess.CalledProcessError as e:
            print(f"{RED}[-] nmap failed (exit {e.returncode}){RESET}")
            return []
        except subprocess.TimeoutExpired:
            print(f"{RED}[-] scan timed out after {timeout}s{RESET}")
            return []

        print(f"\n{CYAN}[*] saved → {xml_path}{RESET}")
        return self._parse(xml_path)

    def _parse(self, xml_path):
        if not os.path.exists(xml_path):
            print(f"{RED}[-] xml not found: {xml_path}{RESET}")
            return []
        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError as e:
            print(f"{RED}[-] couldn't parse nmap xml: {e}{RESET}")
            return []

        ports = []
        for host in root.findall("host"):
            for port in (host.find("ports") or []).findall("port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port.find("service")
                parts = []
                if svc is not None:
                    parts = [svc.get("product", ""), svc.get("version", ""), svc.get("extrainfo", "")]
                ports.append({
                    "port":     int(port.get("portid", 0)),
                    "protocol": port.get("protocol", "tcp"),
                    "state":    "open",
                    "service":  svc.get("name", "unknown") if svc is not None else "unknown",
                    "version":  " ".join(p for p in parts if p) or "—",
                })

        return sorted(ports, key=lambda x: x["port"])

    def display_results(self, results):
        if not results:
            print(f"{RED}[-] no open ports found{RESET}")
            return

        print(f"\n{GREEN}[+] {len(results)} open port(s) on {self.target}{RESET}\n")
        print(f"  {CYAN}{'PORT':<14}{'STATE':<8}{'SERVICE':<16}VERSION{RESET}")
        print(f"  {BLUE}{'─' * 60}{RESET}")
        for p in results:
            print(
                f"  {GREEN}{p['port']}/{p['protocol']:<10}{RESET}"
                f"{GREEN}{p['state']:<8}{RESET}"
                f"{CYAN}{p['service']:<16}{RESET}"
                f"{p['version']}"
            )
        print()
