import subprocess
import platform
import time
from utils.colors import GREEN, RED, CYAN, RESET


class HostDiscovery:
    def __init__(self, target, timeout=1, retries=2):
        if retries < 0:
            raise ValueError(f"retries must be >= 0, got {retries}")
        self.target  = target
        self.timeout = timeout
        self.retries = retries

    def _ping_cmd(self):
        os_name = platform.system().lower()
        if os_name == "windows":
            return ["ping", "-n", "1", "-w", str(self.timeout * 1000), self.target]
        elif os_name == "darwin":
            # macOS -W takes milliseconds, Linux takes seconds
            return ["ping", "-c", "1", "-W", str(self.timeout * 1000), self.target]
        else:
            return ["ping", "-c", "1", "-W", str(self.timeout), self.target]

    def ping(self):
        attempt = 0
        for attempt in range(1, self.retries + 2):
            try:
                t = time.perf_counter()
                result = subprocess.run(
                    self._ping_cmd(),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=self.timeout + 2,
                )
                elapsed = round(time.perf_counter() - t, 4)
                if result.returncode == 0:
                    return {"alive": True, "response_time": elapsed, "attempts": attempt}
            except subprocess.TimeoutExpired:
                pass
            except FileNotFoundError:
                print(f"{RED}[-] ping not found{RESET}")
                break
            except Exception as e:
                print(f"{RED}[-] {e}{RESET}")
                break
        return {"alive": False, "response_time": None, "attempts": attempt}

    def display_result(self, result):
        if result["alive"]:
            ms = round(result["response_time"] * 1000, 2)
            print(f"{GREEN}[+] {self.target} is alive{RESET}  {CYAN}({ms}ms, {result['attempts']} attempt(s)){RESET}")
        else:
            print(f"{RED}[-] {self.target} unreachable after {result['attempts']} attempt(s){RESET}")
