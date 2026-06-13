import subprocess
import platform
import time
from utils.colors import GREEN, RED, YELLOW, CYAN, RESET

class HostDiscovery:
    """
    Pings a target host to confirm it's reachable before we start scanning.

    Handles Windows, Linux, and macOS differences in the ping command,
    retries on failure, and records how long the response took.
    """

    def __init__(self, target: str, timeout: int = 1, retries: int = 2):
        """
        Args:
            target  : IP address or hostname (e.g. "192.168.56.101")
            timeout : Seconds to wait per ping attempt
            retries : Extra attempts if the first ping fails (must be >= 0)
        """
        if retries < 0:
            raise ValueError(f"retries must be >= 0, got {retries}")
        self.target  = target
        self.timeout = timeout
        self.retries = retries

    def _build_ping_command(self) -> list:
        """Returns the correct ping command for the current OS."""
        os_name = platform.system().lower()

        if os_name == "windows":
            return ["ping", "-n", "1", "-w", str(self.timeout * 1000), self.target]
        elif os_name == "darwin":
            # macOS uses milliseconds for -W, unlike Linux
            return ["ping", "-c", "1", "-W", str(self.timeout * 1000), self.target]
        else:
            return ["ping", "-c", "1", "-W", str(self.timeout), self.target]

    def _single_ping(self) -> bool:
        """Fires one ping and returns True if the host replied."""
        command = self._build_ping_command()
        result = subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=self.timeout + 2,
        )
        return result.returncode == 0

    def ping(self) -> dict:
        """
        Pings the target with retry logic.

        Returns:
            {
                "alive":         True/False,
                "response_time": seconds (float) or None if unreachable,
                "attempts":      how many pings it took
            }
        """
        attempt = 0

        for attempt in range(1, self.retries + 2):  # +2 = 1 base + retries
            try:
                start = time.perf_counter()
                alive = self._single_ping()
                elapsed = round(time.perf_counter() - start, 4)

                if alive:
                    return {"alive": True, "response_time": elapsed, "attempts": attempt}

            except subprocess.TimeoutExpired:
                pass  # try again

            except FileNotFoundError:
                print(f"{RED}[-] ping not found on this system.{RESET}")
                break

            except Exception as e:
                print(f"{RED}[-] Unexpected error: {e}{RESET}")
                break

        return {"alive": False, "response_time": None, "attempts": attempt}

    def display_result(self, result: dict) -> None:
        """Prints the ping result to the terminal."""
        alive    = result["alive"]
        rtime    = result["response_time"]
        attempts = result["attempts"]

        if alive:
            ms = round(rtime * 1000, 2)
            print(f"{GREEN}[+] Target {self.target} is alive{RESET}  "
                  f"{CYAN}({ms}ms — {attempts} attempt(s)){RESET}")
        else:
            print(f"{RED}[-] Target {self.target} is unreachable "
                  f"after {attempts} attempt(s) — aborting{RESET}")
