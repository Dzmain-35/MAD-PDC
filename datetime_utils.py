"""
DateTime Utilities for MAD-PDC
Provides centralized date/time handling and clock correction for VM snapshots.

When analysts work in Virtual Machines and revert to snapshots, the system clock
resets to the snapshot date.  This module can detect the correct time by probing
the network case folder (the file server always has the right clock), then set
the local Windows system clock to match.

Usage:
    from datetime_utils import get_current_datetime, sync_clock_from_network

    now = get_current_datetime()

    success, message = sync_clock_from_network(r"\\\\server\\share\\path")
"""

from datetime import datetime
from typing import Tuple, Optional
import os
import subprocess
import platform
import tempfile
import ctypes


def get_current_datetime() -> datetime:
    """
    Get the current datetime.

    All modules in MAD-PDC call this instead of datetime.now() so that
    the clock source is centralised in one place.
    """
    return datetime.now()


def get_network_datetime(network_path: str) -> Tuple[bool, Optional[datetime], str]:
    """
    Get the current date/time from a network file server.

    Creates a temporary file on the network share and reads back the
    modification timestamp assigned by the server, which reflects the
    server's real clock — unaffected by VM snapshot reverts.

    Args:
        network_path: UNC path to the network share (e.g. r"\\\\10.1.64.2\\share").

    Returns:
        (success, server_datetime_or_None, message)
    """
    if not network_path or not os.path.isdir(network_path):
        return False, None, f"Network path not accessible: {network_path}"

    probe_path = os.path.join(network_path, ".mad_time_probe")
    try:
        # Write a small temp file — the server stamps it with its own clock
        with open(probe_path, "w") as f:
            f.write("time_probe")

        # Read back the modification time the server assigned
        server_time = datetime.fromtimestamp(os.path.getmtime(probe_path))

        return True, server_time, f"Server time: {server_time.strftime('%m/%d/%Y %H:%M:%S')}"

    except PermissionError:
        return False, None, "Permission denied writing to network share"
    except OSError as e:
        return False, None, f"Network error: {e}"
    finally:
        # Clean up
        try:
            if os.path.exists(probe_path):
                os.remove(probe_path)
        except OSError:
            pass


def set_system_clock(target: datetime) -> Tuple[bool, str]:
    """
    Set the Windows system clock to a specific datetime.

    Uses the Win32 SetSystemTime API via ctypes.  Requires the process
    to be running with elevated (Administrator) privileges.

    Args:
        target: The datetime to set the system clock to.

    Returns:
        (success, message)
    """
    if platform.system() != "Windows":
        return False, "Setting system clock is only supported on Windows"

    try:
        # SetSystemTime expects UTC, so convert from local time
        import time as _time
        # Calculate UTC offset at the target time
        local_ts = target.timestamp()
        utc_target = datetime.utcfromtimestamp(local_ts)

        class SYSTEMTIME(ctypes.Structure):
            _fields_ = [
                ("wYear", ctypes.c_ushort),
                ("wMonth", ctypes.c_ushort),
                ("wDayOfWeek", ctypes.c_ushort),
                ("wDay", ctypes.c_ushort),
                ("wHour", ctypes.c_ushort),
                ("wMinute", ctypes.c_ushort),
                ("wSecond", ctypes.c_ushort),
                ("wMilliseconds", ctypes.c_ushort),
            ]

        st = SYSTEMTIME()
        st.wYear = utc_target.year
        st.wMonth = utc_target.month
        st.wDayOfWeek = utc_target.weekday()
        st.wDay = utc_target.day
        st.wHour = utc_target.hour
        st.wMinute = utc_target.minute
        st.wSecond = utc_target.second
        st.wMilliseconds = utc_target.microsecond // 1000

        result = ctypes.windll.kernel32.SetSystemTime(ctypes.byref(st))
        if result == 0:
            error_code = ctypes.GetLastError()
            return False, f"SetSystemTime failed (error {error_code})"

        return True, f"System clock set to {target.strftime('%m/%d/%Y %H:%M:%S')}"

    except Exception as e:
        return False, f"Failed to set system clock: {e}"


def sync_clock_from_network(network_path: str) -> Tuple[bool, str]:
    """
    Sync the local system clock using the network file server's time.

    1. Probes the network share to get the server's current datetime
    2. Sets the local Windows system clock to match

    This is the primary clock correction method — it uses the same network
    share that cases are uploaded to, so no NTP or internet is needed.

    Args:
        network_path: UNC path to the network case folder.

    Returns:
        (success, message)
    """
    # Step 1: Get the real time from the file server
    ok, server_time, probe_msg = get_network_datetime(network_path)
    if not ok or server_time is None:
        return False, probe_msg

    # Step 2: Check if the local clock is significantly off
    local_time = datetime.now()
    drift_seconds = abs((server_time - local_time).total_seconds())

    if drift_seconds < 60:
        # Clock is within 1 minute — no correction needed
        return True, f"Clock is accurate (drift: {drift_seconds:.0f}s)"

    # Step 3: Set the system clock to the server time
    ok, set_msg = set_system_clock(server_time)
    if not ok:
        return False, set_msg

    return True, f"Clock corrected from network server ({set_msg})"
