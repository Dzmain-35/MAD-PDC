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
        failed_packages = []

        for package in packages:
            success = run_command(
                [sys.executable, "-m", "pip", "install", package],
                f"Successfully installed {package}"
            )

            if not success:
                failed_packages.append(package)

            normalized = package.lower()
            if normalized == "playwright" or normalized.startswith("playwright=="):
                if success:
                    playwright_requested = True

        if playwright_requested:
            run_command(
                [sys.executable, "-m", "playwright", "install", "--with-deps", "chromium"],
                "Successfully installed Playwright Chromium browser and system dependencies"
            )

        if failed_packages:
            print(f"\n[!] The following packages failed to install: {', '.join(failed_packages)}")
        else:
            print("\n[+] All installations completed successfully.")

    except Exception as e:
        print(f"[!] Unexpected error: {e}")


if __name__ == "__main__":
    install_packages()
