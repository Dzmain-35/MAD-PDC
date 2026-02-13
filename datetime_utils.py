"""
DateTime Utilities for MAD-PDC
Provides centralized date/time handling and Windows clock sync for VM snapshots.

When analysts work in Virtual Machines and revert to snapshots, the system clock
resets to the snapshot date.  Rather than maintaining a software override, this
module can force the real Windows clock to resync via NTP — the same effect as
toggling "Set time automatically" off and back on in Windows Settings.

Usage:
    from datetime_utils import get_current_datetime, sync_system_clock

    # Centralized datetime accessor (drop-in replacement for datetime.now())
    now = get_current_datetime()

    # Force an NTP resync of the system clock (requires admin / elevated)
    success, message = sync_system_clock()
"""

from datetime import datetime
from typing import Tuple
import subprocess
import platform


def get_current_datetime() -> datetime:
    """
    Get the current datetime.

    All modules in MAD-PDC call this instead of datetime.now() so that
    the clock source is centralised in one place.
    """
    return datetime.now()


def sync_system_clock() -> Tuple[bool, str]:
    """
    Force the Windows system clock to resync via NTP.

    Equivalent to toggling *Settings > Time & Language > Set time automatically*
    off and back on.  Restarts the Windows Time service and forces an NTP resync.

    Requires the process to be running with elevated (Administrator) privileges,
    which MAD already needs for Sysmon / process monitoring.

    Returns:
        (success, message) — True with a status string, or False with an error.
    """
    if platform.system() != "Windows":
        return False, "Time sync is only supported on Windows"

    # The sequence mirrors what the Settings toggle does internally:
    #   1. Stop the time service
    #   2. Unregister / re-register to reset state
    #   3. Start the service
    #   4. Force an NTP resync with source rediscovery
    steps = [
        (["net", "stop", "w32time"],                   "Stopping Windows Time service"),
        (["w32tm", "/unregister"],                      "Unregistering time service"),
        (["w32tm", "/register"],                        "Registering time service"),
        (["net", "start", "w32time"],                   "Starting Windows Time service"),
        (["w32tm", "/resync", "/rediscover", "/force"], "Forcing NTP resync"),
    ]

    errors = []
    for cmd, description in steps:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            # net stop returns non-zero if already stopped — that's fine
            if result.returncode != 0 and cmd[0] != "net":
                errors.append(f"{description}: {result.stderr.strip() or result.stdout.strip()}")
        except FileNotFoundError:
            return False, f"Command not found: {cmd[0]}"
        except subprocess.TimeoutExpired:
            errors.append(f"{description}: timed out")
        except Exception as e:
            errors.append(f"{description}: {e}")

    if errors:
        return False, "; ".join(errors)

    return True, f"System clock resynced successfully at {datetime.now().strftime('%m/%d/%Y %H:%M:%S')}"
