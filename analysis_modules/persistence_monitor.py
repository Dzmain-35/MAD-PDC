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
    def _snapshot_scheduled_tasks(self) -> Dict[str, PersistenceEntry]:
        entries: Dict[str, PersistenceEntry] = OrderedDict()
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "XML", "/v"],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if result.returncode != 0:
                return entries
            self._parse_schtasks_xml(result.stdout, entries)
        except FileNotFoundError:
            # schtasks not available (non-Windows)
            pass
        except subprocess.TimeoutExpired:
            print("[PersistenceMonitor] schtasks query timed out")
        except Exception as e:
            print(f"[PersistenceMonitor] schtasks error: {e}")
        return entries

    @staticmethod
    def _parse_schtasks_xml(xml_str: str, entries: Dict[str, PersistenceEntry]):
        """Parse the XML output of schtasks /query /fo XML /v."""
        # schtasks returns multiple XML documents concatenated — wrap them
        wrapped = f"<root>{xml_str}</root>"
        try:
            root = ET.fromstring(wrapped)
        except ET.ParseError:
            # Try cleaning up common issues
            try:
                # Remove XML declarations that appear mid-stream
                import re
                cleaned = re.sub(r'<\?xml[^?]*\?>', '', xml_str)
                wrapped = f"<root>{cleaned}</root>"
                root = ET.fromstring(wrapped)
            except ET.ParseError as e:
                print(f"[PersistenceMonitor] XML parse error: {e}")
                return

        # Namespace used by schtasks XML
        ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

        for task_el in root.iter():
            # Look for Task elements in the namespace
            if task_el.tag.endswith("}Task") or task_el.tag == "Task":
                task_name = "Unknown"
                command = ""
                arguments = ""
                author = ""
                state = ""
                trigger_info = ""

                # Try to extract URI (task name) from RegistrationInfo
                uri_el = task_el.find(".//t:RegistrationInfo/t:URI", ns)
                if uri_el is not None and uri_el.text:
                    task_name = uri_el.text

                author_el = task_el.find(".//t:RegistrationInfo/t:Author", ns)
                if author_el is not None and author_el.text:
                    author = author_el.text

                # Extract command from Actions/Exec
                cmd_el = task_el.find(".//t:Actions/t:Exec/t:Command", ns)
                if cmd_el is not None and cmd_el.text:
                    command = cmd_el.text

                args_el = task_el.find(".//t:Actions/t:Exec/t:Arguments", ns)
                if args_el is not None and args_el.text:
                    arguments = args_el.text

                # Extract triggers summary
                triggers = task_el.find(".//t:Triggers", ns)
                if triggers is not None:
                    trigger_types = []
                    for child in triggers:
                        tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                        trigger_types.append(tag)
                    trigger_info = ", ".join(trigger_types)

                full_command = f"{command} {arguments}".strip() if command else "(no action)"

                # Determine severity based on heuristics
                severity = "low"
                cmd_lower = full_command.lower()
                if any(s in cmd_lower for s in [
                    "powershell", "cmd.exe /c", "mshta", "wscript",
                    "cscript", "rundll32", "regsvr32", "certutil",
                    "bitsadmin", "\\temp\\", "\\tmp\\", "\\appdata\\",
                    "base64", "-enc", "-nop", "-w hidden",
                ]):
                    severity = "high"
                elif any(s in cmd_lower for s in [
                    "\\users\\", "\\programdata\\", ".bat", ".vbs", ".js",
                ]):
                    severity = "medium"

                if not command:
                    continue

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
                        "state": state,
                        "full_path": task_name,
                    },
                )
                entries[entry.key] = entry
