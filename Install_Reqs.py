import subprocess
import sys
from pathlib import Path


def run_command(command, description):
    try:
        result = subprocess.run(
            command,
            check=True,
            text=True,
            capture_output=True
        )
        print(f"[+] {description}")
        if result.stdout.strip():
            print(result.stdout.strip())
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed: {description}")
        if e.stdout:
            print(e.stdout.strip())
        if e.stderr:
            print(e.stderr.strip())
        return False


def install_packages():
    requirements_path = Path("requirements.txt")

    if not requirements_path.exists():
        print("[!] requirements.txt file not found.")
        return

    try:
        with requirements_path.open("r", encoding="utf-8") as file:
            packages = [
                line.strip()
                for line in file
                if line.strip() and not line.strip().startswith("#")
            ]

        if not packages:
            print("[!] requirements.txt is empty.")
            return

        playwright_requested = False

        for package in packages:
            success = run_command(
                [sys.executable, "-m", "pip", "install", package],
                f"Successfully installed {package}"
            )

            if not success:
                print(f"[!] Stopping due to install failure: {package}")
                return

            normalized = package.lower()
            if normalized == "playwright" or normalized.startswith("playwright=="):
                playwright_requested = True

        if playwright_requested:
            success = run_command(
                [sys.executable, "-m", "playwright", "install", "chromium"],
                "Successfully installed Playwright Chromium runtime"
            )

            if not success:
                print("[!] Python packages installed, but Playwright Chromium install failed.")
                return

        print("[+] All installations completed successfully.")

    except Exception as e:
        print(f"[!] Unexpected error: {e}")


if __name__ == "__main__":
    install_packages()
