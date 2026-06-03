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
from scanner.host_discovery import HostDiscovery, CYAN, GREEN, RED, YELLOW, RESET


def banner(target: str) -> None:
    print(f"""{CYAN}
╔══════════════════════════════════════════════════╗
║   Cyber Attack Surface Assessment Framework      ║
║   github.com/harsha823/cyber-attack-surface      ║
╚══════════════════════════════════════════════════╝{RESET}
  {YELLOW}Target :{RESET} {target}
""")


def main():
    # 1. Validate argument 
    if len(sys.argv) != 2:
        print(f"{RED}Usage  : python assessor.py <target-ip>{RESET}")
        print(f"{RED}Example: python assessor.py 192.168.56.101{RESET}")
        sys.exit(1)

    target = sys.argv[1]
    banner(target)

    #  2. Host Discovery 
    print(f"{YELLOW}[*] Starting host discovery...{RESET}")
    hd     = HostDiscovery(target=target, timeout=1, retries=2)
    result = hd.ping()
    hd.display_result(result)

    if not result["alive"]:
        sys.exit(1)

    # Upcoming phases 
    print(f"\n{YELLOW}[*] Port scanning       → Phase 2{RESET}")
    print(f"{YELLOW}[*] Service enumeration → Phase 3{RESET}")
    print(f"{YELLOW}[*] Risk analysis       → Phase 4{RESET}")
    print(f"{YELLOW}[*] Report generation   → Phase 5{RESET}")


if __name__ == "__main__":
    main()
