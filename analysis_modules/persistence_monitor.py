"""
Persistence Monitor
Detects malware persistence mechanisms by baselining and monitoring:
1. Registry Run/RunOnce keys and other autostart locations
2. Scheduled Tasks (Task Scheduler)

Baselines the current state on start, then polls for additions,
modifications, and deletions — firing callbacks when changes occur.
"""

import threading
import time
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Callable, Set, Any
from collections import OrderedDict

try:
    import winreg
except ImportError:
    winreg = None

try:
    import psutil as _psutil
except ImportError:
    _psutil = None

# ── Registry locations commonly abused for persistence ──────────────────
REGISTRY_PERSISTENCE_KEYS = [
    # Run / RunOnce (HKLM)
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
     "HKLM\\...\\Run", "high"),
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
     "HKLM\\...\\RunOnce", "high"),
    # Run / RunOnce (HKCU)
    (winreg.HKEY_CURRENT_USER if winreg else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
     "HKCU\\...\\Run", "high"),
    (winreg.HKEY_CURRENT_USER if winreg else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
     "HKCU\\...\\RunOnce", "high"),
    # Services
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SYSTEM\CurrentControlSet\Services",
     "HKLM\\...\\Services", "medium"),
    # Winlogon
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
     "HKLM\\...\\Winlogon", "high"),
    # Image File Execution Options (debugger hijack)
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
     "HKLM\\...\\IFEO", "critical"),
    # AppInit_DLLs
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
     "HKLM\\...\\Windows (AppInit)", "critical"),
    # Shell extensions
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
     "HKLM\\...\\Shell Folders", "medium"),
    (winreg.HKEY_CURRENT_USER if winreg else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
     "HKCU\\...\\Shell Folders", "medium"),
    # Startup approved
    (winreg.HKEY_CURRENT_USER if winreg else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
     "HKCU\\...\\StartupApproved\\Run", "medium"),
    # RunServices (legacy, still checked by malware)
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
     "HKLM\\...\\RunServices", "high"),
    (winreg.HKEY_CURRENT_USER if winreg else None,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
     "HKCU\\...\\RunServices", "high"),
    # Userinit
    (winreg.HKEY_LOCAL_MACHINE if winreg else None,
     r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
     "HKLM\\...\\Winlogon (Userinit)", "high"),
]


class PersistenceEntry:
    """Represents a single persistence mechanism entry."""

    def __init__(self, source: str, location: str, name: str,
                 value: str, severity: str = "medium",
                 entry_type: str = "registry", extra: Optional[Dict] = None):
        self.source = source          # e.g. "HKCU\\...\\Run"
        self.location = location      # full registry path or task path
        self.name = name              # value name or task name
        self.value = value            # data (exe path, command, etc.)
        self.severity = severity      # low / medium / high / critical
        self.entry_type = entry_type  # "registry" or "scheduled_task"
        self.extra = extra or {}      # additional metadata
        self.first_seen = datetime.now()

    @property
    def key(self) -> str:
        """Unique identifier for deduplication."""
        return f"{self.entry_type}|{self.location}|{self.name}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "location": self.location,
            "name": self.name,
            "value": self.value,
            "severity": self.severity,
            "entry_type": self.entry_type,
            "extra": self.extra,
            "first_seen": self.first_seen.isoformat(),
        }


class PersistenceMonitor:
    """
    Monitors Windows persistence mechanisms (registry + scheduled tasks).

    Usage:
        mon = PersistenceMonitor()
        mon.register_callback(my_handler)   # called with (change_type, entry)
        mon.start_monitoring()
    """

    def __init__(self, poll_interval: float = 5.0):
        self.poll_interval = poll_interval
        self.is_monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.callbacks: List[Callable] = []

        # Baseline snapshots  {entry.key -> PersistenceEntry}
        self.registry_baseline: Dict[str, PersistenceEntry] = OrderedDict()
        self.task_baseline: Dict[str, PersistenceEntry] = OrderedDict()

        # Running log of all detected changes
        self.changes: List[Dict[str, Any]] = []
        self._changes_lock = threading.Lock()

        # PIDs of subprocesses spawned by this monitor (shared with SystemWideMonitor)
        self._internal_pids: Set[int] = set()
        self._internal_pids_lock = threading.Lock()

        # Stats
        self.stats = {
            "registry_entries": 0,
            "scheduled_tasks": 0,
            "total_changes": 0,
            "added": 0,
            "modified": 0,
            "removed": 0,
            "last_scan": None,
        }

    @property
    def internal_pids(self) -> Set[int]:
        """PIDs of subprocesses owned by this monitor (for exclusion from live events)."""
        with self._internal_pids_lock:
            return set(self._internal_pids)

    def _track_subprocess(self, proc: subprocess.Popen):
        """Add a Popen process and its children to the internal PID set."""
        with self._internal_pids_lock:
            self._internal_pids.add(proc.pid)
        # Also track child processes (e.g. conhost.exe spawned by schtasks)
        if _psutil:
            try:
                ps = _psutil.Process(proc.pid)
                for child in ps.children(recursive=True):
                    with self._internal_pids_lock:
                        self._internal_pids.add(child.pid)
            except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                pass

    def _untrack_subprocess(self, proc: subprocess.Popen):
        """Remove a Popen process and its children from the internal PID set."""
        with self._internal_pids_lock:
            self._internal_pids.discard(proc.pid)
            # Clean up any child PIDs that were tracked
            # Keep only PIDs that are still alive and parented to our processes
            self._internal_pids.clear()

    # ── public API ───────────────────────────────────────────────────
    def register_callback(self, callback: Callable):
        """Register a callback: callback(change_type, PersistenceEntry)"""
        self.callbacks.append(callback)

    def start_monitoring(self) -> bool:
        if self.is_monitoring:
            return False
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="PersistenceMonitor"
        )
        self.monitor_thread.start()
        return True

    def stop_monitoring(self) -> bool:
        if not self.is_monitoring:
            return False
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=3)
        return True

    def take_baseline(self) -> Dict[str, int]:
        """Capture current persistence state as the baseline."""
        self.registry_baseline = self._snapshot_registry()
        self.task_baseline = self._snapshot_scheduled_tasks()
        self.stats["registry_entries"] = len(self.registry_baseline)
        self.stats["scheduled_tasks"] = len(self.task_baseline)
        self.stats["last_scan"] = datetime.now().strftime("%H:%M:%S")
        return {
            "registry": len(self.registry_baseline),
            "tasks": len(self.task_baseline),
        }

    def get_all_entries(self) -> List[PersistenceEntry]:
        """Return the full current baseline as a flat list."""
        entries = list(self.registry_baseline.values()) + list(self.task_baseline.values())
        return entries

    def get_changes(self) -> List[Dict[str, Any]]:
        with self._changes_lock:
            return list(self.changes)

    # ── internal: monitoring loop ────────────────────────────────────
    def _monitor_loop(self):
        # Take initial baseline on first run
        if not self.registry_baseline and not self.task_baseline:
            self.take_baseline()
            print(f"[PersistenceMonitor] Baseline captured: "
                  f"{len(self.registry_baseline)} reg entries, "
                  f"{len(self.task_baseline)} tasks")

        while self.is_monitoring:
            try:
                self._poll_registry()
                self._poll_scheduled_tasks()
                self.stats["last_scan"] = datetime.now().strftime("%H:%M:%S")
            except Exception as e:
                print(f"[PersistenceMonitor] Error in poll loop: {e}")
            time.sleep(self.poll_interval)

    def _poll_registry(self):
        current = self._snapshot_registry()
        self._diff_and_notify(
            self.registry_baseline, current, entry_type="registry"
        )
        self.registry_baseline = current
        self.stats["registry_entries"] = len(current)

    def _poll_scheduled_tasks(self):
        current = self._snapshot_scheduled_tasks()
        self._diff_and_notify(
            self.task_baseline, current, entry_type="scheduled_task"
        )
        self.task_baseline = current
        self.stats["scheduled_tasks"] = len(current)

    def _diff_and_notify(self, old: Dict[str, PersistenceEntry],
                         new: Dict[str, PersistenceEntry],
                         entry_type: str):
        old_keys = set(old.keys())
        new_keys = set(new.keys())

        # Added
        for key in new_keys - old_keys:
            entry = new[key]
            self._record_change("added", entry)

        # Removed
        for key in old_keys - new_keys:
            entry = old[key]
            self._record_change("removed", entry)

        # Modified (value changed)
        for key in old_keys & new_keys:
            if old[key].value != new[key].value:
                new[key].extra["previous_value"] = old[key].value
                self._record_change("modified", new[key])

    def _record_change(self, change_type: str, entry: PersistenceEntry):
        change = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "change_type": change_type,
            "entry": entry,
        }
        with self._changes_lock:
            self.changes.append(change)
        self.stats["total_changes"] += 1
        self.stats[change_type] = self.stats.get(change_type, 0) + 1

        for cb in self.callbacks:
            try:
                cb(change_type, entry)
            except Exception as e:
                print(f"[PersistenceMonitor] Callback error: {e}")

    # ── snapshot: registry ───────────────────────────────────────────
    def _snapshot_registry(self) -> Dict[str, PersistenceEntry]:
        entries: Dict[str, PersistenceEntry] = OrderedDict()
        if winreg is None:
            return entries

        for hive, subkey, label, severity in REGISTRY_PERSISTENCE_KEYS:
            if hive is None:
                continue
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                    self._enumerate_values(key, subkey, label, severity, entries)
            except FileNotFoundError:
                pass
            except PermissionError:
                pass
            except OSError:
                pass
        return entries

    @staticmethod
    def _enumerate_values(key, subkey: str, label: str, severity: str,
                          entries: Dict[str, PersistenceEntry]):
        """Read all values from an open registry key."""
        try:
            i = 0
            while True:
                try:
                    name, data, reg_type = winreg.EnumValue(key, i)
                    val_str = str(data) if data is not None else ""
                    entry = PersistenceEntry(
                        source=label,
                        location=subkey,
                        name=name or "(Default)",
                        value=val_str,
                        severity=severity,
                        entry_type="registry",
                        extra={"reg_type": reg_type},
                    )
                    entries[entry.key] = entry
                    i += 1
                except OSError:
                    break
        except Exception:
            pass

    # ── snapshot: scheduled tasks ────────────────────────────────────
    def _run_schtasks(self, args: List[str], timeout: int = 30) -> Optional[str]:
        """Run schtasks via Popen, tracking PIDs so SystemWideMonitor can exclude them."""
        try:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self._track_subprocess(proc)
            try:
                stdout, _ = proc.communicate(timeout=timeout)
                if proc.returncode == 0 and stdout.strip():
                    return stdout
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                print(f"[PersistenceMonitor] schtasks timed out: {args}")
            finally:
                self._untrack_subprocess(proc)
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[PersistenceMonitor] schtasks error ({args}): {e}")
        return None

    def _snapshot_scheduled_tasks(self) -> Dict[str, PersistenceEntry]:
        entries: Dict[str, PersistenceEntry] = OrderedDict()
        # Try XML format first (richer data), fall back to LIST format
        xml_output = self._run_schtasks(["schtasks", "/query", "/fo", "XML", "/v"])
        if xml_output:
            self._parse_schtasks_xml(xml_output, entries)

        # If XML parsing yielded nothing, fall back to LIST format
        if not entries:
            list_output = self._run_schtasks(["schtasks", "/query", "/fo", "LIST", "/v"])
            if list_output:
                self._parse_schtasks_list(list_output, entries)

        return entries

    @staticmethod
    def _parse_schtasks_xml(xml_str: str, entries: Dict[str, PersistenceEntry]):
        """Parse the XML output of schtasks /query /fo XML /v.

        schtasks outputs multiple complete XML documents concatenated
        together, each starting with <?xml ...?>.  We split on those
        declarations and parse each one individually.
        """
        import re
        # Split on XML declarations — each chunk is one task definition
        chunks = re.split(r'<\?xml[^?]*\?>\s*', xml_str)

        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

        for chunk in chunks:
            chunk = chunk.strip()
            if not chunk:
                continue
            try:
                task_el = ET.fromstring(chunk)
            except ET.ParseError:
                continue

            task_name = "Unknown"
            command = ""
            arguments = ""
            author = ""
            trigger_info = ""

            # RegistrationInfo/URI is the task path
            uri_el = task_el.find(".//t:RegistrationInfo/t:URI", ns)
            if uri_el is None:
                uri_el = task_el.find(".//RegistrationInfo/URI")
            if uri_el is not None and uri_el.text:
                task_name = uri_el.text

            author_el = task_el.find(".//t:RegistrationInfo/t:Author", ns)
            if author_el is None:
                author_el = task_el.find(".//RegistrationInfo/Author")
            if author_el is not None and author_el.text:
                author = author_el.text

            # Actions/Exec/Command
            cmd_el = task_el.find(".//t:Actions/t:Exec/t:Command", ns)
            if cmd_el is None:
                cmd_el = task_el.find(".//Actions/Exec/Command")
            if cmd_el is not None and cmd_el.text:
                command = cmd_el.text

            args_el = task_el.find(".//t:Actions/t:Exec/t:Arguments", ns)
            if args_el is None:
                args_el = task_el.find(".//Actions/Exec/Arguments")
            if args_el is not None and args_el.text:
                arguments = args_el.text

            # Triggers summary
            triggers = task_el.find(".//t:Triggers", ns)
            if triggers is None:
                triggers = task_el.find(".//Triggers")
            if triggers is not None:
                trigger_types = []
                for child in triggers:
                    tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                    trigger_types.append(tag)
                trigger_info = ", ".join(trigger_types)

            full_command = f"{command} {arguments}".strip() if command else ""
            if not full_command:
                continue

            severity = PersistenceMonitor._score_task_severity(full_command)

            entry = PersistenceEntry(
                source="Task Scheduler",
                location=task_name,
                name=task_name.rsplit("\\", 1)[-1] if "\\" in task_name else task_name,
                value=full_command,
                severity=severity,
                entry_type="scheduled_task",
                extra={
                    "author": author,
                    "triggers": trigger_info,
                    "full_path": task_name,
                },
            )
            entries[entry.key] = entry

    @staticmethod
    def _parse_schtasks_list(list_str: str, entries: Dict[str, PersistenceEntry]):
        """Parse the LIST output of schtasks /query /fo LIST /v.

        LIST format is line-oriented key: value pairs separated by
        blank lines between tasks.  This is the reliable fallback.
        """
        current: Dict[str, str] = {}

        def _flush(task: Dict[str, str]):
            task_name = task.get("TaskName", "").strip()
            task_to_run = task.get("Task To Run", "").strip()
            if not task_name or not task_to_run or task_to_run == "N/A":
                return
            author = task.get("Author", "").strip()
            severity = PersistenceMonitor._score_task_severity(task_to_run)
            entry = PersistenceEntry(
                source="Task Scheduler",
                location=task_name,
                name=task_name.rsplit("\\", 1)[-1] if "\\" in task_name else task_name,
                value=task_to_run,
                severity=severity,
                entry_type="scheduled_task",
                extra={
                    "author": author,
                    "triggers": task.get("Schedule Type", ""),
                    "full_path": task_name,
                    "status": task.get("Status", ""),
                    "next_run": task.get("Next Run Time", ""),
                    "last_run": task.get("Last Run Time", ""),
                },
            )
            entries[entry.key] = entry

        for line in list_str.splitlines():
            line = line.rstrip()
            if not line:
                if current:
                    _flush(current)
                    current = {}
                continue
            # Lines look like "HostName:    DESKTOP-ABC"
            # or             "Task To Run:  C:\Windows\..."
            colon_idx = line.find(":")
            if colon_idx > 0:
                key = line[:colon_idx].strip()
                value = line[colon_idx + 1:].strip()
                current[key] = value

        # Flush last task
        if current:
            _flush(current)

    @staticmethod
    def _score_task_severity(command: str) -> str:
        cmd_lower = command.lower()
        if any(s in cmd_lower for s in [
            "powershell", "cmd.exe /c", "mshta", "wscript",
            "cscript", "rundll32", "regsvr32", "certutil",
            "bitsadmin", "\\temp\\", "\\tmp\\", "\\appdata\\",
            "base64", "-enc", "-nop", "-w hidden",
        ]):
            return "high"
        if any(s in cmd_lower for s in [
            "\\users\\", "\\programdata\\", ".bat", ".vbs", ".js",
        ]):
            return "medium"
        return "low"
