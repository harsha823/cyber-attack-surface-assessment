# Cyber Attack Surface Assessment Framework

A lightweight, terminal-based tool for mapping the attack surface of a host. Point it at a target IP, and it works through five sequential phases — host discovery, port scanning, service enumeration, risk analysis, and report generation — finishing with a standalone HTML report you can open in any browser.

Built on top of Nmap for port scanning, with custom Python code handling everything else. No heavy frameworks, no external Python dependencies beyond the standard library.

---

## What it does

```
Phase 1 — Host Discovery     Is the target reachable?
Phase 2 — Port Scanning      Which ports are open? (Nmap)
Phase 3 — Service Enumeration What's running on those ports? (banner grabs)
Phase 4 — Risk Analysis      How dangerous is what we found?
Phase 5 — Report Generation  Write an HTML report with remediation steps
```

Sample terminal output:

```
╔══════════════════════════════════════════════════════╗
║     Cyber Attack Surface Assessment Framework        ║
╚══════════════════════════════════════════════════════╝
  Version  : 0.5.0
  Target   : 192.168.56.101
  Started  : 2024-06-01 14:30:22

──────────────────────────────────────────────────────
  Phase 2 — Port Scanning
──────────────────────────────────────────────────────

[+] 4 open port(s) found on 192.168.56.101

  PORT        PROTOCOL  STATE   SERVICE       VERSION
  ────────────────────────────────────────────────────────────
  21/tcp      tcp       open    ftp           vsftpd 3.0.3
  22/tcp      tcp       open    ssh           OpenSSH 7.4
  80/tcp      tcp       open    http          Apache httpd 2.4.6
  3306/tcp    tcp       open    mysql         MySQL 5.7.29
```

---

## Prerequisites

- Python 3.8+
- [Nmap](https://nmap.org/download.html) installed and on your PATH
- Linux, macOS, or Windows (WSL recommended on Windows)

No pip installs required — the tool only uses Python's standard library (`socket`, `subprocess`, `ssl`, `json`, `concurrent.futures`).

---

## Installation

```bash
git clone https://github.com/harsha823/cyber-attack-surface-assessment
cd cyber-attack-surface-assessment
```
That's it. No virtual environment or package installation needed.

Make sure Nmap is installed:

```bash
# Linux
sudo apt install nmap

# macOS
brew install nmap

# Windows — grab the installer from https://nmap.org/download.html
```

---

## Usage

```bash
python assessor.py <target-ip>
```

Examples:

```bash
# Scan a lab machine
python assessor.py 192.168.56.101

# Scan your local machine
python assessor.py 127.0.0.1
```

> **Only run this against hosts you own or have explicit permission to test.** Unauthorized port scanning is illegal in most jurisdictions.

The tool will create two directories as it runs:

- `scans/` — raw Nmap XML output and JSON exports from phases 3 and 4
- `reports/` — the final HTML report

---

## Output

### Terminal

Each phase prints its results live as it runs. Risk levels are colour-coded:

| Colour | Level    | Meaning                              |
|--------|----------|--------------------------------------|
| Red (bold) | CRITICAL | Fix immediately                  |
| Red    | HIGH     | Fix as soon as possible              |
| Yellow | MEDIUM   | Schedule for remediation             |
| Cyan   | LOW      | Review and monitor                   |
| Blue   | INFO     | Informational, no immediate action   |

### HTML Report

After all five phases complete, a self-contained HTML file is written to `reports/`. It includes:

- Executive summary with counts per risk level
- A card for each finding showing port, service, risk level, and banner
- Concrete remediation steps for each service (not just "update your software")
- Scan metadata (target, date, total findings)

The file has no external dependencies — CSS is inline, no JavaScript frameworks. Open it in any browser.

---

## Project structure

```
cyber-attack-surface-assessment/
├── assessor.py                  # Entry point — runs all five phases
│
├── scanner/
│   ├── host_discovery.py        # Phase 1: ping check with retry logic
│   ├── port_scanner.py          # Phase 2: Nmap wrapper, parses XML output
│   └── service_enum.py          # Phase 3: parallel banner grabs
│
├──analyzer/
│    ├── risk_analyzer.py         # Phase 4: service/port risk scoring
│    ├── recommendations.py       # Phase 5: HTML report generation
│
├── scans/                       # Created at runtime — Nmap XML and JSON exports
└── reports/                     # Created at runtime — HTML reports
```

---

## How the phases work

### Phase 1 — Host Discovery

A simple ping check before we waste time scanning. Handles Linux/macOS/Windows differences in the ping command, retries up to 2 times, and measures round-trip time. The assessment aborts here if the host is unreachable.

### Phase 2 — Port Scanning

Wraps Nmap with `-sV --open` to detect service versions on ports 1–1024. The raw XML output is saved to `scans/` for reference, then parsed into a clean list of open port dicts. You can change the port range or scan speed in `assessor.py`.

Three speed profiles are available:

| Profile | Nmap flag | Use case |
|---------|-----------|----------|
| `sneaky` | `-T2` | Slower, less likely to trigger IDS |
| `normal` | `-T3` | Default — good for most situations |
| `fast`   | `-T4` | Lab environments |

### Phase 3 — Service Enumeration

Connects to each open port and grabs whatever the service says first (the "banner"). Runs all connections in parallel using a thread pool so you're not sitting through individual timeouts sequentially.

Each result gets:
- The cleaned banner text
- A parsed version string (prefers Nmap's version, falls back to the banner)
- A confidence level (HIGH/MEDIUM/LOW) based on how much we actually confirmed
- A risk flag if the service is known to be commonly misconfigured

### Phase 4 — Risk Analysis

Scores each finding using two lookup tables — one keyed by service name (`ftp`, `rdp`, etc.) and one keyed by port number. The higher score wins. Low-confidence results are downgraded one level to avoid false alarms from ports where we couldn't confirm what was actually running.

Known risky configurations that get flagged:

| Service | Default Level | Why |
|---------|---------------|-----|
| Telnet  | CRITICAL | Completely unencrypted |
| MongoDB | CRITICAL | Older versions expose data with no auth |
| Redis   | CRITICAL | Often no auth, can be used for RCE |
| FTP     | HIGH | Credentials in plain text |
| RDP     | HIGH | BlueKeep and brute-force risk |
| MySQL   | HIGH | Database shouldn't be network-facing |
| SMTP    | MEDIUM | Open relay risk |
| SSH     | LOW | Secure but verify password auth is off |
| HTTPS   | INFO | Encrypted, still worth checking TLS version |

### Phase 5 — Report Generation

Attaches concrete remediation steps to each finding and writes a standalone HTML file. The terminal output shows the top 2 actions for CRITICAL and HIGH findings; the full list is in the HTML report.

---

## Configuration

The main settings are at the top of `assessor.py`:

```python
# Change the port range
ps = PortScanner(target=target, ports="1-65535", speed="fast")

# Change enumeration timeout (seconds per port)
se = ServiceEnumerator(target=target, timeout=5)
```

To add a new service to the risk scoring, edit the `SERVICE_RISK_MAP` in `risk_analyzer.py`. To add remediation steps for a service, add an entry to `REMEDIATION_MAP` in `recommendations.py`.

---

## Legal notice

This tool is intended for use on systems you own or have written permission to test. Running port scans or vulnerability assessments against systems without authorization is illegal in most countries and may result in criminal charges.

The authors take no responsibility for misuse of this tool.

---

## License

MIT License — see [LICENSE](LICENSE) for details.
