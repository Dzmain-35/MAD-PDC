import subprocess
import sys
import time
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

        # Separate playwright from other packages for special handling
        playwright_requested = False
        regular_packages = []
        for package in packages:
            normalized = package.lower()
            if normalized == "playwright" or normalized.startswith("playwright=="):
                playwright_requested = True
                regular_packages.append(package)
            else:
                regular_packages.append(package)

        # Batch install all packages at once for speed (pip resolves deps in one pass)
        start_time = time.time()
        print(f"[*] Installing {len(regular_packages)} packages in batch...")
        success = run_command(
            [
                sys.executable, "-m", "pip", "install",
                "--no-warn-script-location",
                *regular_packages
            ],
            f"Successfully installed {len(regular_packages)} packages"
        )

        if not success:
            # Fall back to individual installation to identify failures
            print("[*] Batch install failed. Falling back to individual installation...")
            failed_packages = []
            for package in regular_packages:
                pkg_success = run_command(
                    [sys.executable, "-m", "pip", "install", package],
                    f"Successfully installed {package}"
                )
                if not pkg_success:
                    failed_packages.append(package)

            if failed_packages:
                print(f"\n[!] The following packages failed to install: {', '.join(failed_packages)}")
            else:
                print("\n[+] All installations completed successfully (individual mode).")
        else:
            elapsed = time.time() - start_time
            print(f"\n[+] All installations completed successfully in {elapsed:.1f}s.")

        # Install Playwright browsers after pip packages are ready
        if playwright_requested:
            run_command(
                [sys.executable, "-m", "playwright", "install", "--with-deps", "chromium"],
                "Successfully installed Playwright Chromium browser and system dependencies"
            )

    except Exception as e:
        print(f"[!] Unexpected error: {e}")


if __name__ == "__main__":
    install_packages()
