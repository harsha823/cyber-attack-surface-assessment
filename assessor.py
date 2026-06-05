"""
assessor.py
-----------
Main entry point for the Cyber Attack Surface Assessment Framework.

Orchestrates all scanning phases in sequence:
    Phase 1 — Host Discovery
    Phase 2 — Port Scanning
    Phase 3 — Service Enumeration
    Phase 4 — Risk Analysis       (coming next)
    Phase 5 — Report Generation   (coming next)

Usage:
    python assessor.py <target-ip>

Example:
    python assessor.py 192.168.56.101

Author : Cyber Attack Surface Assessment Framework
GitHub : github.com/YOUR-USERNAME/cyber-attack-surface-assessment
"""

import sys
from datetime import datetime
from typing import Optional

from scanner.host_discovery import HostDiscovery
from scanner.port_scanner   import PortScanner
from scanner.service_enum   import ServiceEnumerator


# Terminal colours 
GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

#  Framework version 
VERSION = "0.3.0"   # bump this each time a new phase is added


# Display helpers

def print_banner(target: str) -> None:
    """
    Prints the framework header banner with target and timestamp.

    Args:
        target : The IP address or hostname being assessed.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"""
{CYAN}{BOLD}
╔═════════════════════════════════════════════════════════╗
║    Cyber Attack Surface Assessment Framework            ║
║    github.com/harsha823/cyber-attack-surface-assessment ║
╚═════════════════════════════════════════════════════════╝
{RESET}
  {YELLOW}Version  :{RESET} {VERSION}
  {YELLOW}Target   :{RESET} {target}
  {YELLOW}Started  :{RESET} {now}
""")


def print_phase_header(number: int, title: str) -> None:
    """
    Prints a consistent section divider before each phase.

    Args:
        number : Phase number (1–5).
        title  : Short phase description.
    """
    print(f"\n{BLUE}{'─' * 54}{RESET}")
    print(f"{BOLD}{CYAN}  Phase {number} — {title}{RESET}")
    print(f"{BLUE}{'─' * 54}{RESET}\n")


def print_summary(
    target   : str,
    start_time: datetime,
    ports    : list,
    services : list,
) -> None:
    """
    Prints the framework summary after all phases complete.

    Shows total counts, execution time, and next steps.

    Args:
        target     : Target IP or hostname.
        start_time : datetime when the assessment started.
        ports      : List of open port dicts from Phase 2.
        services   : List of enriched service dicts from Phase 3.
    """
    end_time  = datetime.now()
    duration  = round((end_time - start_time).total_seconds(), 2)
    flagged   = [s for s in services if s.get("flagged")]

    print(f"\n{BLUE}{'═' * 54}{RESET}")
    print(f"{BOLD}{GREEN}  Assessment Summary — {target}{RESET}")
    print(f"{BLUE}{'═' * 54}{RESET}")
    print(f"  {YELLOW}Target         :{RESET} {target}")
    print(f"  {YELLOW}Completed      :{RESET} {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {YELLOW}Total duration :{RESET} {duration}s")
    print(f"  {BLUE}{'─' * 38}{RESET}")
    print(f"  {YELLOW}Open ports     :{RESET} {GREEN}{len(ports)}{RESET}")
    print(f"  {YELLOW}Services found :{RESET} {GREEN}{len(services)}{RESET}")
    print(f"  {YELLOW}Risky services :{RESET} "
          f"{RED}{len(flagged)}{RESET}" if flagged
          else f"  {YELLOW}Risky services :{RESET} {GREEN}0{RESET}")
    print(f"  {BLUE}{'─' * 38}{RESET}")
    print(f"  {YELLOW}Phase 4        :{RESET} Risk Analysis       → coming next")
    print(f"  {YELLOW}Phase 5        :{RESET} Report Generation   → coming next")
    print(f"{BLUE}{'═' * 54}{RESET}\n")


# Main

def main() -> None:
    """
    Entry point — validates input, runs all phases in sequence,
    and prints the final summary.
    """

    #  Validate CLI argument 
    if len(sys.argv) != 2:
        print(f"\n{RED}  Usage  : python assessor.py <target-ip>{RESET}")
        print(f"{RED}  Example: python assessor.py 192.168.56.101{RESET}\n")
        sys.exit(1)

    target     = sys.argv[1]
    start_time = datetime.now()

    print_banner(target)

    #  Phase 1 — Host Discovery 
    print_phase_header(1, "Host Discovery")

    hd           = HostDiscovery(target=target, timeout=1, retries=2)
    host_result  = hd.ping()
    hd.display_result(host_result)

    if not host_result["alive"]:
        print(f"\n{RED}  Assessment aborted — target is unreachable.{RESET}\n")
        sys.exit(1)

    #  Phase 2 — Port Scanning
    print_phase_header(2, "Port Scanning")

    ps    = PortScanner(target=target, ports="1-1024", speed="normal")
    ports = ps.run_scan()
    ps.display_results(ports)

    if not ports:
        print(f"{RED}  No open ports found — assessment complete.{RESET}")
        print_summary(target, start_time, ports=[], services=[])
        sys.exit(0)

    #  Phase 3 — Service Enumeration 
    print_phase_header(3, "Service Enumeration")

    se       = ServiceEnumerator(target=target, timeout=3)
    services = se.enumerate(ports)
    se.display_results(services)
    se.export_json(services)

    #  Final Summary
    print_summary(target, start_time, ports, services)


if __name__ == "__main__":
    main()
