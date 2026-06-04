"""
assessor.py
-----------
Main entry point for the Cyber Attack Surface Assessment Framework.

Usage:
    python assessor.py <target-ip>

Example:
    python assessor.py 192.168.56.101
"""

import sys
from scanner.host_discovery import HostDiscovery
from scanner.port_scanner   import PortScanner

CYAN   = "\033[96m"
YELLOW = "\033[93m"
RED    = "\033[91m"
RESET  = "\033[0m"


def banner(target: str) -> None:
    print(f"""
{CYAN}
╔════════════════════════════════════════════════════╗
║   Cyber Attack Surface Assessment Framework        ║
║github.com/harsha823/cyber-attack-surface-assessment║
╚════════════════════════════════════════════════════╝
  {RESET}
  {YELLOW}Target :{RESET} {target}
""")


def main():
    # ── 1. Validate argument ───────────────────────────────────────────
    if len(sys.argv) != 2:
        print(f"{RED}Usage  : python assessor.py <target-ip>{RESET}")
        print(f"{RED}Example: python assessor.py 192.168.56.101{RESET}")
        sys.exit(1)

    target = sys.argv[1]
    banner(target)

    # ── 2. Host Discovery ──────────────────────────────────────────────
    print(f"{YELLOW}[*] Starting host discovery...{RESET}")
    hd     = HostDiscovery(target=target, timeout=1, retries=2)
    result = hd.ping()
    hd.display_result(result)

    if not result["alive"]:
        sys.exit(1)

    # ── 3. Port Scan ───────────────────────────────────────────────────
    print(f"\n{YELLOW}[*] Starting port scan...{RESET}")
    ps      = PortScanner(target=target, ports="1-1024", speed="normal")
    ports   = ps.run_scan()
    ps.display_results(ports)

    if not ports:
        print(f"{RED}[-] No open ports found — nothing to enumerate{RESET}")
        sys.exit(0)

    # ── Upcoming phases ────────────────────────────────────────────────
    print(f"{YELLOW}[*] Service enumeration → Phase 3{RESET}")
    print(f"{YELLOW}[*] Risk analysis       → Phase 4{RESET}")
    print(f"{YELLOW}[*] Report generation   → Phase 5{RESET}")


if __name__ == "__main__":
    main()
