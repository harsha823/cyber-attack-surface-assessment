import socket
import ssl
import json
import os
import concurrent.futures
from datetime import datetime
from utils.colors import GREEN, RED, YELLOW, CYAN, BLUE, BOLD, RESET

# services that wait for a client to speak first get a generic nudge;
# ones that banner immediately get None so we just listen
PROBES = {
    "http":     b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    "https":    b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    "http-alt": b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    "ftp":      None,
    "ssh":      None,
    "smtp":     None,
    "pop3":     None,
    "imap":     None,
    "mysql":    None,
    "rdp":      None,
}

SSL_PORTS = {443, 8443, 993, 995, 465, 636, 989, 990}

# things we want to flag even before the full risk analysis
RISKY = {
    "ftp":    "unencrypted — creds in plain text",
    "telnet": "unencrypted — all traffic visible on the wire",
    "smtp":   "check for open relay",
    "pop3":   "unencrypted mail — creds in plain text",
    "mysql":  "database exposed — should not be network-facing",
    "mssql":  "database exposed — should not be network-facing",
    "vnc":    "remote desktop — check for weak/missing auth",
    "rdp":    "remote desktop — high-value target, check patch level",
    "smb":    "check for EternalBlue (MS17-010)",
    "snmp":   "check for default community strings",
    "ldap":   "check for anonymous bind",
}


class ServiceEnumerator:
    def __init__(self, target, timeout=3, max_workers=10, output_dir="scans"):
        self.target      = target
        self.timeout     = timeout
        self.max_workers = max_workers
        self.output_dir  = output_dir

    def _grab(self, port, service):
        probe     = PROBES.get(service, b"\r\n")
        use_ssl   = port in SSL_PORTS or service in ("https", "imaps", "pop3s", "smtps")

        def _read(sock):
            if probe:
                sock.sendall(probe)
            return sock.recv(2048).decode("utf-8", errors="ignore").strip()

        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
                    raw.settimeout(self.timeout)
                    try:
                        with ctx.wrap_socket(raw, server_hostname=self.target) as s:
                            s.connect((self.target, port))
                            return _read(s)
                    except ssl.SSLError:
                        # port looks encrypted but TLS handshake failed — try plain
                        pass

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.target, port))
                return _read(s)

        except (socket.timeout, ConnectionRefusedError, OSError):
            return ""
        except Exception:
            return ""

    def _clean(self, raw):
        # first non-empty line, max 120 chars
        for line in raw.splitlines():
            line = line.strip()
            if line:
                return line[:120]
        return "—"

    def _confidence(self, banner, nmap_ver):
        # both sources agree = HIGH, one = MEDIUM, neither = LOW
        has_banner = banner not in ("—", "", "Unknown")
        has_ver    = nmap_ver not in ("—", "", "Unknown")
        if has_banner and has_ver:
            return "HIGH"
        if has_banner or has_ver:
            return "MEDIUM"
        return "LOW"

    def _scan_one(self, port_info):
        port     = port_info["port"]
        service  = port_info.get("service", "unknown")
        nmap_ver = port_info.get("version", "—")

        raw    = self._grab(port, service)
        banner = self._clean(raw)
        # prefer nmap's version string; fall back to whatever the banner said
        version    = nmap_ver if nmap_ver not in ("—", "") else (banner if banner != "—" else "Unknown")
        confidence = self._confidence(banner, nmap_ver)
        risk_note  = RISKY.get(service, "")

        return {
            **port_info,
            "banner":        banner,
            "version":       version,
            "confidence":    confidence,
            "risk_note":     risk_note,
            "flagged":       bool(risk_note),
            "enumerated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    def enumerate(self, ports):
        if not ports:
            print(f"{RED}[-] no ports to enumerate{RESET}")
            return []

        started = datetime.now()
        print(f"{YELLOW}[*] enumerating {len(ports)} service(s) on {self.target}...{RESET}\n")

        results = []
        errors  = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            fmap = {pool.submit(self._scan_one, p): p for p in ports}
            for future in concurrent.futures.as_completed(fmap):
                try:
                    results.append(future.result())
                except Exception as e:
                    errors += 1
                    print(f"{RED}[-] port {fmap[future].get('port', '?')}: {e}{RESET}")

        elapsed = round((datetime.now() - started).total_seconds(), 2)
        if errors:
            print(f"{YELLOW}[!] {errors} port(s) failed{RESET}")
        print(f"{CYAN}[*] done in {elapsed}s{RESET}\n")

        return sorted(results, key=lambda x: x["port"])

    def export_json(self, results):
        if not results:
            return None
        os.makedirs(self.output_dir, exist_ok=True)
        ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
        filepath = os.path.join(self.output_dir, f"{self.target.replace('.', '_')}_services_{ts}.json")
        data = {
            "meta": {
                "target":        self.target,
                "exported_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total":         len(results),
                "flagged":       sum(1 for r in results if r["flagged"]),
            },
            "services": results,
        }
        try:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2, default=str)
            print(f"{GREEN}[+] services → {filepath}{RESET}")
            return filepath
        except OSError as e:
            print(f"{RED}[-] couldn't write json: {e}{RESET}")
            return None

    def display_results(self, results):
        if not results:
            print(f"{RED}[-] nothing to show{RESET}")
            return

        flagged  = [r for r in results if r["flagged"]]
        hi_conf  = sum(1 for r in results if r["confidence"] == "HIGH")
        low_conf = sum(1 for r in results if r["confidence"] == "LOW")

        print(f"{BOLD}{GREEN}[+] services — {self.target}{RESET}\n")
        print(f"  {CYAN}{'PORT':<12}{'SERVICE':<12}{'VERSION / BANNER':<40}{'CONF':<10}FLAG{RESET}")
        print(f"  {BLUE}{'─' * 76}{RESET}")

        for r in results:
            port_str = f"{r['port']}/{r['protocol']}"
            ver      = r["version"][:38]
            flag     = f"{RED}⚠ RISK{RESET}" if r["flagged"] else f"{GREEN}ok{RESET}"
            conf_col = {"HIGH": GREEN, "MEDIUM": YELLOW, "LOW": RED}.get(r["confidence"], RESET)
            print(
                f"  {GREEN}{port_str:<12}{RESET}"
                f"{CYAN}{r['service']:<12}{RESET}"
                f"{ver:<40}"
                f"{conf_col}{r['confidence']:<18}{RESET}"
                f"{flag}"
            )

        if flagged:
            print(f"\n  {BOLD}{RED}⚠  risky services{RESET}")
            print(f"  {BLUE}{'─' * 76}{RESET}")
            for r in flagged:
                print(f"  {RED}{r['port']}/{r['protocol']:<10}{RESET}{YELLOW}{r['service']:<14}{RESET}{r['risk_note']}")

        print(f"\n  total: {len(results)}  flagged: {RED}{len(flagged)}{RESET}  "
              f"high-conf: {GREEN}{hi_conf}{RESET}  low-conf: {YELLOW}{low_conf}{RESET}\n")
