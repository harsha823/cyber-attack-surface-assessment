import sys
import argparse
from datetime import datetime

from scanner.host_discovery import HostDiscovery
from scanner.port_scanner import PortScanner
from scanner.service_enum import ServiceEnumerator
from analyzer.risk_analyzer import RiskAnalyzer
from analyzer.recommendations import ReportGenerator
from utils.colors import GREEN, RED, YELLOW, CYAN, BLUE, BOLD, RESET

VERSION = "0.6.0"


def parse_args():
    p = argparse.ArgumentParser(
        prog="assessor.py",
        description="Map the attack surface of a host — open ports, services, risk scores, HTML report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python assessor.py 192.168.56.101
  python assessor.py 192.168.56.101 --ports 1-65535 --speed fast
  python assessor.py 192.168.56.101 --ports 22,80,443,3306 --speed sneaky
  python assessor.py 10.0.0.1 --timeout 5 --workers 20 --report-dir /tmp/reports
        """,
    )
    p.add_argument("target", help="IP or hostname to scan")
    p.add_argument("--ports",      default="1-1024",  metavar="RANGE",
                   help='port range or list — "1-1024" (default), "1-65535", "22,80,443"')
    p.add_argument("--speed",      default="normal",  choices=["sneaky", "normal", "fast"],
                   help="nmap speed: sneaky (-T2), normal (-T3, default), fast (-T4)")
    p.add_argument("--timeout",    default=3,         type=int, metavar="SECS",
                   help="per-port banner grab timeout (default: 3)")
    p.add_argument("--workers",    default=10,        type=int, metavar="N",
                   help="parallel threads for service enumeration (default: 10)")
    p.add_argument("--scan-dir",   default="scans",   metavar="DIR",
                   help="where to save nmap xml and json exports (default: scans/)")
    p.add_argument("--report-dir", default="reports", metavar="DIR",
                   help="where to write the HTML report (default: reports/)")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p.parse_args()


def banner(target, args):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════╗
║     Cyber Attack Surface Assessment Framework        ║
║     github.com/harsha823/cyber-attack-surface        ║
╚══════════════════════════════════════════════════════╝{RESET}

  {YELLOW}Version{RESET}  {VERSION}
  {YELLOW}Target {RESET}  {target}
  {YELLOW}Ports  {RESET}  {args.ports}
  {YELLOW}Speed  {RESET}  {args.speed}
  {YELLOW}Started{RESET}  {now}
""")


def phase(n, title):
    print(f"\n{BLUE}{'─' * 54}{RESET}")
    print(f"{BOLD}{CYAN}  Phase {n} — {title}{RESET}")
    print(f"{BLUE}{'─' * 54}{RESET}\n")


def summary(target, started, ports, services, risks, report_path):
    elapsed  = round((datetime.now() - started).total_seconds(), 2)
    critical = sum(1 for r in risks if r.get("risk_level") == "CRITICAL")
    high     = sum(1 for r in risks if r.get("risk_level") == "HIGH")
    medium   = sum(1 for r in risks if r.get("risk_level") == "MEDIUM")
    low      = sum(1 for r in risks if r.get("risk_level") in ("LOW", "INFO"))

    print(f"\n{BLUE}{'═' * 54}{RESET}")
    print(f"{BOLD}{GREEN}  done — {target}{RESET}")
    print(f"{BLUE}{'═' * 54}{RESET}")
    print(f"  {YELLOW}duration  {RESET} {elapsed}s")
    print(f"  {YELLOW}ports     {RESET} {len(ports)}")
    print(f"  {YELLOW}services  {RESET} {len(services)}")
    print(f"  {BLUE}{'─' * 38}{RESET}")
    print(f"  {YELLOW}critical  {RESET} {RED}{BOLD}{critical}{RESET}")
    print(f"  {YELLOW}high      {RESET} {RED}{high}{RESET}")
    print(f"  {YELLOW}medium    {RESET} {YELLOW}{medium}{RESET}")
    print(f"  {YELLOW}low/info  {RESET} {CYAN}{low}{RESET}")
    print(f"  {BLUE}{'─' * 38}{RESET}")
    print(f"  {YELLOW}report    {RESET} {GREEN}{report_path}{RESET}")
    print(f"{BLUE}{'═' * 54}{RESET}\n")


def main():
    args    = parse_args()
    target  = args.target
    started = datetime.now()

    banner(target, args)

    phase(1, "Host Discovery")
    hd     = HostDiscovery(target=target, timeout=1, retries=2)
    result = hd.ping()
    hd.display_result(result)
    if not result["alive"]:
        print(f"\n{RED}  target unreachable — aborting.{RESET}\n")
        sys.exit(1)

    phase(2, "Port Scanning")
    ps    = PortScanner(target=target, ports=args.ports, speed=args.speed, scan_dir=args.scan_dir)
    ports = ps.run_scan()
    ps.display_results(ports)
    if not ports:
        print(f"{RED}  no open ports found.{RESET}")
        summary(target, started, [], [], [], "N/A")
        sys.exit(0)

    phase(3, "Service Enumeration")
    se       = ServiceEnumerator(target=target, timeout=args.timeout, max_workers=args.workers, output_dir=args.scan_dir)
    services = se.enumerate(ports)
    se.display_results(services)
    se.export_json(services)

    phase(4, "Risk Analysis")
    ra    = RiskAnalyzer(target=target, output_dir=args.scan_dir)
    risks = ra.analyze(services)
    ra.display_results(risks)
    ra.export_json(risks)

    phase(5, "Report Generation")
    rg          = ReportGenerator(target=target, output_dir=args.report_dir)
    rg.display_summary(risks)
    report_path = rg.generate(risks)

    summary(target, started, ports, services, risks, report_path or "N/A")


if __name__ == "__main__":
    main()
