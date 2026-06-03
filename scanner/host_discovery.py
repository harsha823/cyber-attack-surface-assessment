"""
host_discovery.py
-----------------
Checks whether a target host is alive before running any scans.

Usage:
    from scanner.host_discovery import HostDiscovery

    hd = HostDiscovery(target="192.168.56.101")
    result = hd.ping()
    hd.display_result(result)
"""

import subprocess
import platform
import time


#Terminal colours (no external libraries needed)
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"


class HostDiscovery:
    """
    Checks whether a target host is reachable on the network.

    Features:
        - Cross-platform  (Windows / Linux / macOS)
        - Retry logic     (re-pings on failure before giving up)
        - Response time   (measures how long the ping took)
        - Colour output   (green = alive, red = dead)
    """

    def __init__(self, target: str, timeout: int = 1, retries: int = 2):
        """
        Args:
            target  : IP address or hostname  (e.g. "192.168.56.101")
            timeout : Seconds to wait per ping attempt  (default: 1)
            retries : Extra attempts if first ping fails (default: 2)
        """
        self.target  = target
        self.timeout = timeout
        self.retries = retries

    #Private helpers 

    def _build_ping_command(self) -> list:
        """
        Returns the correct ping command for the current OS.

            Windows  → ping -n 1 -w <ms>
            Linux    → ping -c 1 -W <sec>
            macOS    → ping -c 1 -W <ms>
        """
        os_name = platform.system().lower()

        if os_name == "windows":
            return ["ping", "-n", "1", "-w", str(self.timeout * 1000), self.target]

        elif os_name == "darwin":   # macOS uses milliseconds for -W
            return ["ping", "-c", "1", "-W", str(self.timeout * 1000), self.target]

        else:                       # Linux
            return ["ping", "-c", "1", "-W", str(self.timeout), self.target]

    def _single_ping(self) -> bool:
        """
        Fires one ping and returns True if the host replied.
        """
        command = self._build_ping_command()

        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=self.timeout + 2
        )
        return result.returncode == 0

    #Public methods 

    def ping(self) -> dict:
        """
        Pings the target, retrying up to self.retries times on failure.

        Returns a result dict:
            {
                "alive"        : bool,
                "response_time": float | None,   # seconds, or None if dead
                "attempts"     : int
            }
        """
        attempts = 0

        for attempt in range(1, self.retries + 2):   # +2 = 1 base + retries
            attempts = attempt

            try:
                start  = time.perf_counter()
                alive  = self._single_ping()
                elapsed = round(time.perf_counter() - start, 4)

                if alive:
                    return {
                        "alive"        : True,
                        "response_time": elapsed,
                        "attempts"     : attempts
                    }

            except subprocess.TimeoutExpired:
                pass   # timed out — try again

            except FileNotFoundError:
                print(f"{RED}[-] Error: ping utility not found on this system.{RESET}")
                break

            except Exception as e:
                print(f"{RED}[-] Unexpected error: {e}{RESET}")
                break

        return {
            "alive"        : False,
            "response_time": None,
            "attempts"     : attempts
        }

    def display_result(self, result: dict) -> None:
        """
        Prints a formatted summary of the ping result.

        Args:
            result : the dict returned by ping()
        """
        target   = self.target
        alive    = result["alive"]
        rtime    = result["response_time"]
        attempts = result["attempts"]

        if alive:
            ms = round(rtime * 1000, 2)
            print(f"{GREEN}[+] Target {target} is alive{RESET}  "
                  f"{CYAN}({ms}ms — {attempts} attempt(s)){RESET}")
        else:
            print(f"{RED}[-] Target {target} is unreachable "
                  f"after {attempts} attempt(s) — aborting{RESET}")
