"""
Process Handlers
Business logic for process monitoring and analysis operations.
"""

import os
import threading
import subprocess
import platform
from tkinter import messagebox, filedialog
from typing import TYPE_CHECKING, Optional, Dict, Any, List, Set

import customtkinter as ctk
import tkinter as tk

from typography import Fonts

if TYPE_CHECKING:
    from ui.app import ForensicAnalysisGUI


class ProcessHandlers:
    """Handler class for process monitoring business logic"""

    def __init__(self, app: 'ForensicAnalysisGUI'):
        self.app = app
        self.popup_count_by_rule: Dict[str, int] = {}

    @property
    def process_monitor(self):
        return self.app.process_monitor

    @property
    def process_tree(self):
        return self.app.process_tree

    @property
    def pid_to_tree_item(self) -> Dict[int, str]:
        return self.app.pid_to_tree_item

    # ==================== PROCESS MONITORING ====================
    def toggle_process_monitoring(self):
        """Toggle process monitoring on/off"""
        if not self.app.process_monitor_active:
            self.process_monitor.start_monitoring(callback=self.app.on_new_process_detected)
            self.app.process_monitor_active = True
            self.app.btn_toggle_process_monitor.configure(text="Stop Monitoring")
            self.start_process_auto_refresh()
        else:
            self.process_monitor.stop_monitoring()
            self.app.process_monitor_active = False
            self.app.btn_toggle_process_monitor.configure(text="Start Monitoring")

    def start_process_auto_refresh(self):
        """Start auto-refreshing process list"""
        if self.app.process_monitor_active:
            self.refresh_process_list()
            self.app.root.after(
                self.app.auto_refresh_interval,
                self.start_process_auto_refresh
            )

    # ==================== PROCESS LIST MANAGEMENT ====================
    def refresh_process_list(self):
        """Refresh the process tree with parent-child hierarchy using incremental updates"""
        # Check if a filter is active
        search_text = self.app.process_search_entry.get().strip() if hasattr(self.app, 'process_search_entry') else ""
        filter_choice = self.app.process_filter_var.get() if hasattr(self.app, 'process_filter_var') else "All Processes"

        if search_text or filter_choice != "All Processes":
            self.filter_processes()
            return

        processes = self.process_monitor.get_all_processes()
        process_map = {proc['pid']: proc for proc in processes}
        current_pids = set(process_map.keys())
        existing_pids = set(self.pid_to_tree_item.keys())

        # Determine changes
        pids_to_add = current_pids - existing_pids
        dead_pids = existing_pids - current_pids
        potentially_updated_pids = current_pids & existing_pids

        # Handle new process highlighting
        if self.app.process_tree_initial_load:
            new_pids: Set[int] = set()
        else:
            new_pids = pids_to_add

        # Save expanded and selected state
        expanded_pids = set()
        selected_pid = None

        for pid in existing_pids:
            if pid in self.pid_to_tree_item:
                item_id = self.pid_to_tree_item[pid]
                try:
                    if self.process_tree.exists(item_id):
                        if self.process_tree.item(item_id, 'open'):
                            expanded_pids.add(pid)
                except:
                    pass

        selection = self.process_tree.selection()
        if selection:
            try:
                values = self.process_tree.item(selection[0], 'values')
                if values and len(values) > 0:
                    selected_pid = int(values[0])
            except:
                pass

        # Remove dead processes
        for pid in dead_pids:
            if pid in self.pid_to_tree_item:
                try:
                    self.process_tree.delete(self.pid_to_tree_item[pid])
                except:
                    pass
                del self.app.pid_to_tree_item[pid]

        # Update existing processes
        for pid in potentially_updated_pids:
            if pid not in self.pid_to_tree_item:
                continue

            proc = process_map[pid]
            item_id = self.pid_to_tree_item[pid]

            try:
                if not self.process_tree.exists(item_id):
                    new_pids.add(pid)
                    del self.app.pid_to_tree_item[pid]
                    continue

                current_values = self.process_tree.item(item_id, 'values')
                yara_status, tags = self._get_process_status(proc, pid, new_pids)

                if len(current_values) > 3 and current_values[3] != yara_status:
                    self.process_tree.item(
                        item_id,
                        values=(pid, proc['name'], proc.get('exe', 'N/A'), yara_status),
                        tags=tags
                    )
            except Exception:
                if pid in self.pid_to_tree_item:
                    del self.app.pid_to_tree_item[pid]
                pids_to_add.add(pid)
                if not self.app.process_tree_initial_load:
                    new_pids.add(pid)

        # Add new processes
        if pids_to_add:
            self._add_new_processes(processes, process_map, pids_to_add, new_pids, expanded_pids)

        # Restore selection
        if selected_pid and selected_pid in self.pid_to_tree_item:
            try:
                self.process_tree.selection_set(self.pid_to_tree_item[selected_pid])
                self.process_tree.see(self.pid_to_tree_item[selected_pid])
            except:
                pass

        # Mark initial load as complete
        if self.app.process_tree_initial_load:
            self.app.process_tree_initial_load = False

    def _get_process_status(self, proc: Dict, pid: int, new_pids: Set[int]) -> tuple:
        """Get YARA status and tags for a process"""
        import psutil

        is_suspended = False
        try:
            process_status = psutil.Process(pid).status()
            is_suspended = process_status == psutil.STATUS_STOPPED
        except:
            pass

        yara_status = "No"
        tags = ()

        if is_suspended:
            yara_status = "SUSPENDED"
            tags = ('suspended',)
        elif proc.get('threat_detected'):
            yara_rule = proc.get('yara_rule', 'Unknown')
            if yara_rule and yara_rule != 'Unknown':
                scan_results = proc.get('scan_results', {})
                all_rules = scan_results.get('all_rules', [yara_rule])
                if len(all_rules) > 1:
                    yara_status = f"{yara_rule} +{len(all_rules) - 1}"
                else:
                    yara_status = f"{yara_rule}"
            else:
                matches = proc.get('yara_matches', 0)
                yara_status = f"{matches} matches" if matches else "YES"
            tags = ('threat',)
        elif proc.get('whitelisted', False):
            yara_status = "BENIGN"
            tags = ('benign',)
        elif pid in new_pids:
            tags = ('new',)
        elif proc['name'].lower() in ['system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe']:
            tags = ('system',)

        return yara_status, tags

    def _add_new_processes(
            self,
            processes: List[Dict],
            process_map: Dict[int, Dict],
            pids_to_add: Set[int],
            new_pids: Set[int],
            expanded_pids: Set[int]
    ):
        """Add new processes to the tree with hierarchy"""
        children_map: Dict[int, List[Dict]] = {}
        root_processes = []

        for proc in processes:
            ppid = proc.get('ppid')
            if ppid and ppid in process_map and ppid != proc['pid']:
                if ppid not in children_map:
                    children_map[ppid] = []
                children_map[ppid].append(proc)
            else:
                root_processes.append(proc)

        def add_process_tree(proc, parent_id=""):
            pid = proc['pid']

            if pid in self.pid_to_tree_item:
                try:
                    if self.process_tree.exists(self.pid_to_tree_item[pid]):
                        if pid in children_map:
                            for child in children_map[pid]:
                                add_process_tree(child, self.pid_to_tree_item[pid])
                        return
                except:
                    pass

            name = proc['name']
            exe = proc.get('exe', 'N/A')
            yara_status, tags = self._get_process_status(proc, pid, new_pids)

            item_id = self.process_tree.insert(
                parent_id,
                "end",
                text=f"  {name}",
                values=(pid, name, exe, yara_status),
                tags=tags,
                open=pid in expanded_pids
            )

            self.app.pid_to_tree_item[pid] = item_id

            if pid in children_map:
                for child in children_map[pid]:
                    add_process_tree(child, item_id)

        for proc in root_processes:
            if proc['pid'] in pids_to_add or proc['pid'] not in self.pid_to_tree_item:
                add_process_tree(proc)

        # Handle remaining new child processes
        remaining_new_pids = [pid for pid in pids_to_add if pid not in self.pid_to_tree_item]
        for pid in remaining_new_pids:
            if pid in process_map:
                proc = process_map[pid]
                ppid = proc.get('ppid')

                parent_item_id = ""
                if ppid and ppid in self.pid_to_tree_item:
                    try:
                        if self.process_tree.exists(self.pid_to_tree_item[ppid]):
                            parent_item_id = self.pid_to_tree_item[ppid]
                    except:
                        pass

                add_process_tree(proc, parent_item_id)

    def filter_processes(self):
        """Filter processes by search and filter criteria"""
        search_text = self.app.process_search_entry.get().strip().lower()
        filter_choice = self.app.process_filter_var.get() if hasattr(self.app, 'process_filter_var') else "All Processes"

        if not search_text and filter_choice == "All Processes":
            # Clear and refresh
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)
            self.app.pid_to_tree_item.clear()

            was_initial_load = self.app.process_tree_initial_load
            self.app.process_tree_initial_load = True
            self.refresh_process_list()
            self.app.process_tree_initial_load = was_initial_load
            return

        processes = self.process_monitor.get_all_processes()
        process_map = {proc['pid']: proc for proc in processes}

        # Build parent-child relationships
        children_map: Dict[int, List[Dict]] = {}
        for proc in processes:
            ppid = proc.get('ppid')
            if ppid and ppid in process_map and ppid != proc['pid']:
                if ppid not in children_map:
                    children_map[ppid] = []
                children_map[ppid].append(proc)

        # Find matching processes
        matching_pids = set()
        for proc in processes:
            pid_str = str(proc['pid'])
            name_lower = proc['name'].lower()

            search_match = not search_text or (search_text in pid_str or search_text in name_lower)

            filter_match = True
            if filter_choice == "YARA Matches Only":
                yara_rule = proc.get('yara_rule')
                filter_match = (proc.get('threat_detected', False) and
                               yara_rule and yara_rule != 'No_YARA_Hit')
            elif filter_choice == "Benign Only":
                filter_match = proc.get('whitelisted', False)
            elif filter_choice == "Not Scanned":
                filter_match = not proc.get('threat_detected', False) and not proc.get('whitelisted', False)

            if search_match and filter_match:
                matching_pids.add(proc['pid'])

        # Get all children of matching processes
        def get_all_children(pid):
            child_pids = set()
            if pid in children_map:
                for child in children_map[pid]:
                    child_pid = child['pid']
                    child_pids.add(child_pid)
                    child_pids.update(get_all_children(child_pid))
            return child_pids

        pids_to_show = set(matching_pids)
        for pid in matching_pids:
            pids_to_show.update(get_all_children(pid))

        # Clear and rebuild tree
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        self.app.pid_to_tree_item.clear()

        # Build filtered tree
        def add_process_to_tree(proc, parent_id=""):
            pid = proc['pid']
            name = proc['name']
            exe = proc.get('exe', 'N/A')

            yara_status = "No"
            tags = ()
            if proc.get('threat_detected'):
                yara_rule = proc.get('yara_rule', 'Unknown')
                if yara_rule and yara_rule != 'Unknown':
                    scan_results = proc.get('scan_results', {})
                    all_rules = scan_results.get('all_rules', [yara_rule])
                    if len(all_rules) > 1:
                        yara_status = f"{yara_rule} +{len(all_rules) - 1}"
                    else:
                        yara_status = f"{yara_rule}"
                else:
                    matches = proc.get('yara_matches', 0)
                    yara_status = f"{matches} matches" if matches else "YES"
                tags = ('threat',)
            elif name.lower() in ['system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe']:
                tags = ('system',)

            item_id = self.process_tree.insert(
                parent_id,
                "end",
                text=f"  {name}",
                values=(pid, name, exe, yara_status),
                tags=tags,
                open=True
            )

            self.app.pid_to_tree_item[pid] = item_id

            if pid in children_map:
                for child in children_map[pid]:
                    if child['pid'] in pids_to_show:
                        add_process_to_tree(child, item_id)

        # Add root processes
        root_pids = []
        for pid in pids_to_show:
            if pid in process_map:
                proc = process_map[pid]
                ppid = proc.get('ppid')
                if ppid not in pids_to_show or ppid not in process_map or ppid == proc['pid']:
                    root_pids.append(pid)

        for pid in sorted(root_pids):
            if pid in process_map:
                add_process_to_tree(process_map[pid])

    def clear_process_search(self):
        """Clear the process search and show all processes"""
        self.app.process_search_entry.delete(0, tk.END)
        self.refresh_process_list()

    # ==================== PROCESS SCANNING ====================
    def scan_selected_process(self):
        """Scan selected process with YARA"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to scan")
            return

        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])

        def scan():
            result = self.process_monitor.scan_process(pid)
            if 'error' in result:
                self.app.root.after(0, lambda: messagebox.showerror("Scan Error", result['error']))
            else:
                matches_found = result.get('matches_found', False)
                rule = result.get('rule', 'No_YARA_Hit')

                # Update monitored_processes
                self._update_scan_results(pid, result, matches_found, rule)

                if matches_found and rule != 'No_YARA_Hit':
                    self.app.total_yara_matches += 1
                    self.app.root.after(0, self.app.update_yara_match_badge)

                    if self.should_show_popup(rule):
                        self.app.root.after(0, lambda: self._show_threat_alert(pid, result))
                else:
                    msg = f"PID {pid} Scan Complete\n\nNo threats detected."
                    self.app.root.after(0, lambda: messagebox.showinfo("Scan Results", msg))

                self.app.root.after(0, self.refresh_process_list)

        threading.Thread(target=scan, daemon=True).start()

    def _update_scan_results(self, pid: int, result: Dict, matches_found: bool, rule: str):
        """Update monitored_processes with scan results"""
        import psutil

        if pid not in self.process_monitor.monitored_processes:
            try:
                proc = psutil.Process(pid)
                self.process_monitor.monitored_processes[pid] = {
                    'pid': pid,
                    'name': proc.name(),
                    'exe': proc.exe() if proc.exe() else "N/A",
                    'scan_results': result,
                    'threat_detected': matches_found,
                    'yara_rule': rule if matches_found else None
                }
            except:
                self.process_monitor.monitored_processes[pid] = {
                    'pid': pid,
                    'scan_results': result,
                    'threat_detected': matches_found,
                    'yara_rule': rule if matches_found else None
                }
        else:
            self.process_monitor.monitored_processes[pid]['scan_results'] = result
            self.process_monitor.monitored_processes[pid]['threat_detected'] = matches_found
            self.process_monitor.monitored_processes[pid]['yara_rule'] = rule if matches_found else None

    def _show_threat_alert(self, pid: int, result: Dict):
        """Show threat alert popup"""
        import psutil

        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc_exe = proc.exe() if proc.exe() else "N/A"
        except:
            proc_name = "Unknown"
            proc_exe = "N/A"

        rule = result.get('rule', 'Unknown')
        threat_score = result.get('threat_score', 0)
        risk_level = result.get('risk_level', 'Unknown')
        strings = result.get('strings', [])
        all_rules = result.get('all_rules', [rule])

        colors = self.app.colors

        alert = ctk.CTkToplevel(self.app.root)
        alert.title("Threat Detected")
        alert.geometry("700x650")
        alert.minsize(600, 500)
        alert.attributes('-topmost', True)

        main_frame = ctk.CTkFrame(alert, fg_color=colors["red_dark"])
        main_frame.pack(fill="both", expand=True, padx=2, pady=2)

        header_frame = ctk.CTkFrame(main_frame, fg_color=colors["red_dark"])
        header_frame.pack(fill="x", padx=10, pady=(15, 10))

        title = ctk.CTkLabel(
            header_frame,
            text="MALICIOUS PROCESS DETECTED",
            font=Fonts.title_large,
            text_color="white"
        )
        title.pack()

        content_frame = ctk.CTkFrame(main_frame, fg_color=colors["red_dark"])
        content_frame.pack(fill="both", expand=True, padx=10, pady=5)

        rules_display = ', '.join(all_rules) if len(all_rules) > 1 else rule

        details_frame = ctk.CTkFrame(content_frame, fg_color="#1a1a1a", corner_radius=8)
        details_frame.pack(fill="x", padx=10, pady=10)

        details = f"""PID: {pid}
Name: {proc_name}
Path: {proc_exe}

YARA Rule(s): {rules_display}
Threat Score: {threat_score}
Risk Level: {risk_level}"""

        details_label = ctk.CTkLabel(
            details_frame,
            text=details,
            font=Fonts.body,
            justify="left",
            text_color="white"
        )
        details_label.pack(pady=15, padx=15, anchor="w")

        if strings:
            strings_header = ctk.CTkLabel(
                content_frame,
                text=f"Matched Strings ({len(strings)}):",
                font=Fonts.body_bold,
                text_color="white"
            )
            strings_header.pack(pady=(5, 5), padx=10, anchor="w")

            strings_container = ctk.CTkFrame(content_frame, fg_color="#1a1a1a", corner_radius=8)
            strings_container.pack(fill="both", expand=True, padx=10, pady=(0, 10))

            strings_frame = ctk.CTkScrollableFrame(
                strings_container,
                fg_color="#2b2b2b",
                height=250
            )
            strings_frame.pack(fill="both", expand=True, padx=5, pady=5)

            for i, s in enumerate(strings, 1):
                s_display = s[:100] + "..." if len(s) > 100 else s
                string_label = ctk.CTkLabel(
                    strings_frame,
                    text=f"{i}. {s_display}",
                    font=Fonts.helper,
                    text_color="white",
                    anchor="w",
                    justify="left"
                )
                string_label.pack(anchor="w", pady=2, padx=5, fill="x")

        footer_frame = ctk.CTkFrame(main_frame, fg_color=colors["red_dark"])
        footer_frame.pack(fill="x", padx=10, pady=(5, 15))

        btn_close = ctk.CTkButton(
            footer_frame,
            text="Close",
            command=alert.destroy,
            fg_color=colors["navy"],
            hover_color=colors["dark_blue"],
            width=120,
            height=35
        )
        btn_close.pack(pady=5)

    def scan_all_processes(self):
        """Scan all processes with YARA"""
        if not messagebox.askyesno(
            "Confirm Scan All",
            "This will scan ALL running processes. This may take some time.\n\nContinue?"
        ):
            return

        processes = self.process_monitor.get_all_processes()
        total_processes = len(processes)

        # Create progress window
        progress_window = ctk.CTkToplevel(self.app.root)
        progress_window.title("Scanning Processes")
        progress_window.geometry("500x200")
        progress_window.attributes('-topmost', True)

        frame = ctk.CTkFrame(progress_window, fg_color="gray20")
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        title_label = ctk.CTkLabel(frame, text="Scanning All Processes", font=Fonts.title_medium, text_color="white")
        title_label.pack(pady=10)

        progress_label = ctk.CTkLabel(
            frame, text=f"Scanning process 0 of {total_processes}",
            font=Fonts.body, text_color="white"
        )
        progress_label.pack(pady=10)

        progress_bar = ctk.CTkProgressBar(frame, width=400)
        progress_bar.pack(pady=10)
        progress_bar.set(0)

        stats_label = ctk.CTkLabel(
            frame, text="Threats found: 0 | Benign: 0 | Errors: 0",
            font=Fonts.helper, text_color="white"
        )
        stats_label.pack(pady=10)

        scan_stats = {'scanned': 0, 'threats': 0, 'benign': 0, 'errors': 0}

        def scan_all():
            for i, proc in enumerate(processes):
                pid = proc['pid']

                self.app.root.after(0, lambda i=i: progress_label.configure(
                    text=f"Scanning PID {pid} ({i+1} of {total_processes})"
                ))
                self.app.root.after(0, lambda i=i: progress_bar.set((i + 1) / total_processes))

                try:
                    result = self.process_monitor.scan_process(pid)

                    if 'error' not in result:
                        matches_found = result.get('matches_found', False)
                        rule = result.get('rule', 'No_YARA_Hit')

                        self._update_scan_results(pid, result, matches_found, rule)

                        if matches_found and rule != 'No_YARA_Hit':
                            scan_stats['threats'] += 1
                        else:
                            scan_stats['benign'] += 1
                    else:
                        scan_stats['errors'] += 1

                    scan_stats['scanned'] += 1

                    self.app.root.after(0, lambda: stats_label.configure(
                        text=f"Threats found: {scan_stats['threats']} | Benign: {scan_stats['benign']} | Errors: {scan_stats['errors']}"
                    ))

                except Exception as e:
                    scan_stats['errors'] += 1
                    print(f"[ERROR] Failed to scan PID {pid}: {e}")

            self.app.root.after(0, lambda: progress_label.configure(text="Scan Complete!"))
            self.app.root.after(0, self.refresh_process_list)

            summary_msg = f"""Scan Complete!

Total Scanned: {scan_stats['scanned']}
Threats Detected: {scan_stats['threats']}
Benign Processes: {scan_stats['benign']}
Errors: {scan_stats['errors']}"""

            self.app.root.after(0, lambda: messagebox.showinfo("Scan Complete", summary_msg))
            self.app.root.after(0, progress_window.destroy)

        threading.Thread(target=scan_all, daemon=True).start()

    def should_show_popup(self, rule_name: str) -> bool:
        """Determine if a popup should be shown for this YARA rule"""
        if not rule_name or rule_name == 'No_YARA_Hit':
            return False

        count = self.popup_count_by_rule.get(rule_name, 0)

        if count < self.app.max_popups_per_rule:
            self.popup_count_by_rule[rule_name] = count + 1
            return True
        else:
            print(f"Popup suppressed for {rule_name} (limit: {self.app.max_popups_per_rule} per rule)")
            return False

    # ==================== PROCESS CONTROL ====================
    def kill_selected_process(self):
        """Kill selected process"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to kill")
            return

        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])
        name = item['values'][1]

        if messagebox.askyesno("Confirm Kill", f"Are you sure you want to kill process {name} (PID {pid})?"):
            success = self.process_monitor.kill_process(pid)
            if success:
                messagebox.showinfo("Success", f"Process {pid} terminated")
                self.refresh_process_list()
            else:
                messagebox.showerror("Error", f"Failed to kill process {pid}")

    def suspend_selected_process(self):
        """Suspend/pause selected process"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to suspend")
            return

        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])

        success = self.process_monitor.suspend_process(pid)
        if success:
            self.refresh_process_list()
        else:
            messagebox.showerror("Error", f"Failed to suspend process {pid}")

    def resume_selected_process(self):
        """Resume suspended process"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to resume")
            return

        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])

        success = self.process_monitor.resume_process(pid)
        if success:
            messagebox.showinfo("Success", f"Process {pid} resumed")
            self.refresh_process_list()
        else:
            messagebox.showerror("Error", f"Failed to resume process {pid}")

    def open_folder_location(self):
        """Open the folder containing the selected process's executable"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to view")
            return

        item = self.process_tree.item(selection[0])
        file_path = item['values'][2]  # File Path column

        if not file_path or file_path == "N/A":
            messagebox.showerror("Error", "Process does not have an accessible file path")
            return

        try:
            folder_path = os.path.dirname(file_path)

            if not os.path.exists(folder_path):
                messagebox.showerror("Error", f"Folder does not exist: {folder_path}")
                return

            system = platform.system()
            if system == "Windows":
                subprocess.run(['explorer', '/select,', file_path])
            elif system == "Darwin":
                subprocess.run(['open', '-R', file_path])
            else:
                subprocess.run(['xdg-open', folder_path])

        except Exception as e:
            messagebox.showerror("Error", f"Failed to open folder location: {str(e)}")

    def focus_process_by_pid(self, target_pid: int):
        """Focus on a specific process in the tree by PID"""
        try:
            if target_pid not in self.pid_to_tree_item:
                print(f"PID {target_pid} not found in process tree yet")
                self.refresh_process_list()
                self.app.root.after(1000, lambda: self.focus_process_by_pid(target_pid))
                return

            item_id = self.pid_to_tree_item[target_pid]

            parent = self.process_tree.parent(item_id)
            while parent:
                self.process_tree.item(parent, open=True)
                parent = self.process_tree.parent(parent)

            self.process_tree.selection_set(item_id)
            self.process_tree.see(item_id)
            self.process_tree.focus(item_id)

            print(f"Focused on process PID {target_pid}")

        except Exception as e:
            print(f"Error focusing on PID {target_pid}: {e}")
