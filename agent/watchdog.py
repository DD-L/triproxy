from __future__ import annotations

import argparse
import subprocess
import sys
import time


def run_watchdog(config_path: str) -> None:
    while True:
        proc = subprocess.Popen([sys.executable, "-m", "agent.web_daemon", config_path])
        code = proc.wait()
        if code == 0:
            break
        time.sleep(3)


def main() -> None:
    parser = argparse.ArgumentParser(description="TriProxy Agent Web Daemon Watchdog")
    parser.add_argument("config", help="path to agent yaml config")
    args = parser.parse_args()
    run_watchdog(args.config)


if __name__ == "__main__":
    main()

