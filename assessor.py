"""
assessor.py — Main entry point for the Cyber Attack Surface Assessment Framework.

Runs five sequential phases against a target host:
    1. Host Discovery   — is the target even alive?
    2. Port Scanning    — which ports are open?
    3. Service Enum     — what's actually running on those ports?
    4. Risk Analysis    — how dangerous is what we found?
    5. Report Gen       — produce a readable HTML report

Usage:
    python assessor.py <target-ip>
    python assessor.py 192.168.56.101
"""

import sys
from datetime import datetime
from typing import List

from scanner.host_discovery import HostDiscovery
from scanner.port_scanner import PortScanner
from scanner.service_enum import ServiceEnumerator
from analyzer.risk_analyzer import RiskAnalyzer
from analyzer.recommendations import ReportGenerator

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

VERSION = "0.5.0"


def print_banner(target: str) -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"""
{CYAN}{BOLD}
╔══════════════════════════════════════════════════════╗
║     Cyber Attack Surface Assessment Framework        ║
║     github.com/harsha823/cyber-attack-surface        ║
╚══════════════════════════════════════════════════════╝
{RESET}
  {YELLOW}Version  :{RESET} {VERSION}
  {YELLOW}Target   :{RESET} {target}
  {YELLOW}Started  :{RESET} {now}
""")


def print_phase_header(number: int, title: str) -> None:
    print(f"\n{BLUE}{'─' * 54}{RESET}")
    print(f"{BOLD}{CYAN}  Phase {number} — {title}{RESET}")
    print(f"{BLUE}{'─' * 54}{RESET}\n")


def print_summary(target, start_time, ports, services, risks, report_path):
    end_time = datetime.now()
    duration = round((end_time - start_time).total_seconds(), 2)

    critical = sum(1 for r in risks if r.get("risk_level") == "CRITICAL")
    high     = sum(1 for r in risks if r.get("risk_level") == "HIGH")
    medium   = sum(1 for r in risks if r.get("risk_level") == "MEDIUM")
    low      = sum(1 for r in risks if r.get("risk_level") == "LOW")

    print(f"\n{BLUE}{'═' * 54}{RESET}")
    print(f"{BOLD}{GREEN}  Assessment Complete — {target}{RESET}")
    print(f"{BLUE}{'═' * 54}{RESET}")
    print(f"  {YELLOW}Completed      :{RESET} {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {YELLOW}Total duration :{RESET} {duration}s")
    print(f"  {BLUE}{'─' * 38}{RESET}")
    print(f"  {YELLOW}Open ports     :{RESET} {len(ports)}")
    print(f"  {YELLOW}Services found :{RESET} {len(services)}")
    print(f"  {BLUE}{'─' * 38}{RESET}")
    print(f"  {YELLOW}Critical       :{RESET} {RED}{BOLD}{critical}{RESET}")
    print(f"  {YELLOW}High           :{RESET} {RED}{high}{RESET}")
    print(f"  {YELLOW}Medium         :{RESET} {YELLOW}{medium}{RESET}")
    print(f"  {YELLOW}Low / Info     :{RESET} {CYAN}{low}{RESET}")
    print(f"  {BLUE}{'─' * 38}{RESET}")
    print(f"  {YELLOW}Report         :{RESET} {GREEN}{report_path}{RESET}")
    print(f"{BLUE}{'═' * 54}{RESET}\n")


def main():
    if len(sys.argv) != 2:
        print(f"\n{RED}  Usage  : python assessor.py <target-ip>{RESET}")
        print(f"{RED}  Example: python assessor.py 192.168.56.101{RESET}\n")
        sys.exit(1)

    target = sys.argv[1]
    start_time = datetime.now()

    print_banner(target)

    # Phase 1: make sure the host is actually up before wasting time scanning
    print_phase_header(1, "Host Discovery")
    hd = HostDiscovery(target=target, timeout=1, retries=2)
    host_result = hd.ping()
    hd.display_result(host_result)

    if not host_result["alive"]:
        print(f"\n{RED}  Assessment aborted — target unreachable.{RESET}\n")
        sys.exit(1)

    # Phase 2: find open ports
    print_phase_header(2, "Port Scanning")
    ps = PortScanner(target=target, ports="1-1024", speed="normal")
    ports = ps.run_scan()
    ps.display_results(ports)

    if not ports:
        print(f"{RED}  No open ports found — assessment complete.{RESET}")
        print_summary(target, start_time, [], [], [], "N/A")
        sys.exit(0)

    # Phase 3: grab banners and identify what's running
    print_phase_header(3, "Service Enumeration")
    se = ServiceEnumerator(target=target, timeout=3)
    services = se.enumerate(ports)
    se.display_results(services)
    se.export_json(services)

    # Phase 4: score each finding and flag anything dangerous
    print_phase_header(4, "Risk Analysis")
    ra = RiskAnalyzer(target=target)
    risks = ra.analyze(services)
    ra.display_results(risks)
    ra.export_json(risks)

    # Phase 5: write the HTML report
    print_phase_header(5, "Report Generation")
    rg = ReportGenerator(target=target)
    rg.display_summary(risks)
    report_path = rg.generate(risks)

    print_summary(target, start_time, ports, services, risks, report_path or "N/A")


if __name__ == "__main__":
    main()
