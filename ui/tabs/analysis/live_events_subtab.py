"""
Live Events Subtab
System-wide event monitoring interface (File, Registry, Network, Process, DNS).
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Optional, Dict, Any

from typography import Fonts
from ui.theme import Theme

if TYPE_CHECKING:
    from ui.app import ForensicAnalysisGUI


class LiveEventsSubtab:
    """Subtab for system-wide live event monitoring"""

    def __init__(self, app: 'ForensicAnalysisGUI', parent: ctk.CTkFrame):
        self.app = app
        self.parent = parent
        self.colors = app.colors
        self.frame = None

        # Monitor state
        self.monitor_state = {
            "monitor": None,
            "monitoring": False,
            "current_filter": None,
            "update_job": None,
            "last_update_time": datetime.now() - timedelta(days=1),
            "event_count": 0
        }

        # UI elements
        self.monitor_btn = None
        self.monitor_btn_text = None
        self.status_label = None
        self.sysmon_status = None
        self.stats_label = None
        self.events_tree = None
        self.event_type_buttons = {}
        self.pid_filter_entry = None
        self.regex_filter_entry = None
        self.include_children_var = None
        self.suspicious_var = None
        self.process_info_panel = None
        self.process_info_label = None

    def create(self) -> ctk.CTkFrame:
        """Create the Live Events subtab for system-wide monitoring"""
        self.frame = ctk.CTkFrame(self.parent, fg_color="transparent")

        # Header with title
        header = ctk.CTkFrame(self.frame, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=10)

        title = ctk.CTkLabel(
            header, text="Live System Events",
            font=Fonts.title_large,
            text_color="white"
        )
        title.pack(side="left")

        subtitle = ctk.CTkLabel(
            header,
            text="Real-time monitoring: File • Registry • Network • Process • DNS",
            font=Fonts.helper, text_color="gray60"
        )
        subtitle.pack(side="left", padx=20)

        # Main content area
        content = ctk.CTkFrame(self.frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        # Control panel
        self._create_control_panel(content)

        # Filter panel
        self._create_filter_panel(content)

        # Process info panel (shown when PID filter active)
        self._create_process_info_panel(content)

        # Events display
        self._create_events_display(content)

        # Connect button commands
        self._connect_commands()

        # Store toggle function for auto-start
        self.app.live_events_toggle_monitoring = self.toggle_monitoring

        return self.frame

    def _create_control_panel(self, parent):
        """Create control panel with start/stop and stats"""
        control_panel = ctk.CTkFrame(parent, fg_color=self.colors["navy"], height=120)
        control_panel.pack(fill="x", pady=(0, 10))
        control_panel.pack_propagate(False)

        # Row 1: Start/Stop and Status
        row1 = ctk.CTkFrame(control_panel, fg_color="transparent")
        row1.pack(fill="x", padx=10, pady=(10, 5))

        # Start/Stop button
        self.monitor_btn_text = tk.StringVar(value="▶ Start Monitoring")
        self.monitor_btn = ctk.CTkButton(
            row1,
            textvariable=self.monitor_btn_text,
            command=self.toggle_monitoring,
            height=40,
            width=180,
            font=Fonts.label_large,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"]
        )
        self.monitor_btn.pack(side="left", padx=(0, 20))

        # Status label
        self.status_label = ctk.CTkLabel(
            row1,
            text="● Monitoring: Stopped",
            font=Fonts.body_large,
            text_color="gray50"
        )
        self.status_label.pack(side="left", padx=10)

        # Sysmon status
        self.sysmon_status = ctk.CTkLabel(
            row1,
            text="",
            font=Fonts.helper,
            text_color="gray60"
        )
        self.sysmon_status.pack(side="left", padx=10)

        # Export and Clear buttons
        export_btn = ctk.CTkButton(
            row1,
            text="💾 Export CSV",
            command=self.export_events_to_csv,
            height=35,
            width=120,
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["red"]
        )
        export_btn.pack(side="right", padx=5)

        clear_btn = ctk.CTkButton(
            row1,
            text="🗑 Clear Events",
            command=self.clear_events_display,
            height=35,
            width=120,
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["red"]
        )
        clear_btn.pack(side="right", padx=5)

        # Row 2: Statistics
        row2 = ctk.CTkFrame(control_panel, fg_color="transparent")
        row2.pack(fill="x", padx=10, pady=5)

        self.stats_label = ctk.CTkLabel(
            row2,
            text="Total: 0 | File: 0 | Registry: 0 | Network: 0 | Process: 0 | DNS: 0",
            font=Fonts.body,
            text_color="gray60"
        )
        self.stats_label.pack(side="left")

    def _create_filter_panel(self, parent):
        """Create filter controls"""
        filter_panel = ctk.CTkFrame(parent, fg_color=self.colors["navy"])
        filter_panel.pack(fill="x", pady=(0, 10))

        # Filter row 1: Event types
        filter_row1 = ctk.CTkFrame(filter_panel, fg_color="transparent")
        filter_row1.pack(fill="x", padx=10, pady=(10, 5))

        filter_label1 = ctk.CTkLabel(
            filter_row1,
            text="Event Type:",
            font=Fonts.body_bold
        )
        filter_label1.pack(side="left", padx=(0, 10))

        # Event type filter buttons
        filter_types = ["All", "File", "Registry", "Network", "Process", "Thread", "DNS"]
        for ftype in filter_types:
            btn = ctk.CTkButton(
                filter_row1,
                text=ftype,
                command=lambda f=ftype: self.set_event_type_filter(f),
                height=30,
                width=85,
                fg_color=self.colors["red"] if ftype == "All" else "transparent",
                hover_color=self.colors["navy"],
                border_width=1,
                border_color=self.colors["red"]
            )
            btn.pack(side="left", padx=3)
            self.event_type_buttons[ftype] = btn

        # Suspicious only toggle
        self.suspicious_var = tk.BooleanVar(value=False)
        suspicious_check = ctk.CTkCheckBox(
            filter_row1,
            text="🚨 Suspicious Only",
            variable=self.suspicious_var,
            command=lambda: self.apply_filters() if self.monitor_state["monitoring"] else None,
            font=Fonts.body_bold,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"]
        )
        suspicious_check.pack(side="right", padx=10)

        # Filter row 2: PID and regex
        filter_row2 = ctk.CTkFrame(filter_panel, fg_color="transparent")
        filter_row2.pack(fill="x", padx=10, pady=(5, 10))

        # PID filter
        pid_filter_label = ctk.CTkLabel(
            filter_row2,
            text="PID Filter:",
            font=Fonts.helper
        )
        pid_filter_label.pack(side="left", padx=(0, 5))

        self.pid_filter_entry = ctk.CTkEntry(
            filter_row2,
            placeholder_text="Enter PID (optional)",
            width=150,
            height=30
        )
        self.pid_filter_entry.pack(side="left", padx=5)

        # Include child processes checkbox
        self.include_children_var = tk.BooleanVar(value=False)
        include_children_checkbox = ctk.CTkCheckBox(
            filter_row2,
            text="Include children",
            variable=self.include_children_var,
            font=Fonts.helper,
            width=120
        )
        include_children_checkbox.pack(side="left", padx=5)

        # Path regex filter
        regex_filter_label = ctk.CTkLabel(
            filter_row2,
            text="Path Regex:",
            font=Fonts.helper
        )
        regex_filter_label.pack(side="left", padx=(20, 5))

        self.regex_filter_entry = ctk.CTkEntry(
            filter_row2,
            placeholder_text="Enter regex pattern (e.g., .*\\Run\\.*)",
            width=300,
            height=30
        )
        self.regex_filter_entry.pack(side="left", padx=5)

        apply_filter_btn = ctk.CTkButton(
            filter_row2,
            text="Apply Filters",
            command=self.apply_filters,
            height=30,
            width=100,
            fg_color=self.colors["red"]
        )
        apply_filter_btn.pack(side="left", padx=10)

        clear_filter_btn = ctk.CTkButton(
            filter_row2,
            text="Clear Filters",
            command=self.clear_filters,
            height=30,
            width=100,
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["red"]
        )
        clear_filter_btn.pack(side="left", padx=5)

    def _create_process_info_panel(self, parent):
        """Create process info panel (shown when PID filter active)"""
        self.process_info_panel = ctk.CTkFrame(
            parent, fg_color=self.colors["dark_blue"], height=80
        )
        self.process_info_label = ctk.CTkLabel(
            self.process_info_panel,
            text="",
            font=Fonts.helper,
            text_color="white",
            anchor="w",
            justify="left"
        )
        self.process_info_label.pack(fill="both", expand=True, padx=15, pady=10)
        # Store reference for packing later
        self._events_frame = None

    def _create_events_display(self, parent):
        """Create events treeview"""
        events_frame = ctk.CTkFrame(parent, fg_color="gray20")
        events_frame.pack(fill="both", expand=True)
        self._events_frame = events_frame

        # Scrollbars
        events_vsb = tk.Scrollbar(events_frame, orient="vertical", bg="#1a1a1a")
        events_vsb.pack(side="right", fill="y")

        events_hsb = tk.Scrollbar(events_frame, orient="horizontal", bg="#1a1a1a")
        events_hsb.pack(side="bottom", fill="x")

        # TreeView for events
        columns = ("time", "pid", "process", "type", "operation", "path", "result")
        self.events_tree = ttk.Treeview(
            events_frame,
            columns=columns,
            show="headings",
            height=25,
            yscrollcommand=events_vsb.set,
            xscrollcommand=events_hsb.set
        )

        # Configure columns
        self.events_tree.heading("time", text="Time")
        self.events_tree.heading("pid", text="PID")
        self.events_tree.heading("process", text="Process")
        self.events_tree.heading("type", text="Type")
        self.events_tree.heading("operation", text="Operation")
        self.events_tree.heading("path", text="Path / Target")
        self.events_tree.heading("result", text="Result")

        self.events_tree.column("time", width=100, minwidth=100)
        self.events_tree.column("pid", width=60, minwidth=60)
        self.events_tree.column("process", width=120, minwidth=100)
        self.events_tree.column("type", width=80, minwidth=80)
        self.events_tree.column("operation", width=150, minwidth=120)
        self.events_tree.column("path", width=400, minwidth=200)
        self.events_tree.column("result", width=100, minwidth=80)

        # Style the tree
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                        background="#1a1a1a",
                        foreground="white",
                        fieldbackground="#1a1a1a",
                        borderwidth=0)
        style.configure("Treeview.Heading",
                        background="#0d1520",
                        foreground="white",
                        borderwidth=1)
        style.map("Treeview",
                  background=[("selected", "#dc2626")])

        # Tag for suspicious events
        self.events_tree.tag_configure('suspicious', background='#5c1c1c', foreground='#ff6b6b')

        self.events_tree.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        events_vsb.config(command=self.events_tree.yview)
        events_hsb.config(command=self.events_tree.xview)

        # Context menu
        self._create_events_context_menu()

    def _create_events_context_menu(self):
        """Create context menu for events tree"""
        menu_config = Theme.get_menu_config()
        events_context_menu = tk.Menu(self.events_tree, tearoff=0, **menu_config)
        events_context_menu.add_command(label="🔍 Focus on PID", command=self.focus_on_pid)
        events_context_menu.add_command(label="📋 Copy Path", command=self.copy_path_to_clipboard)
        events_context_menu.add_separator()
        events_context_menu.add_command(
            label="➕ Extract IOCs to Case",
            command=lambda: self.app.add_live_event_iocs_to_case(self.events_tree)
        )
        events_context_menu.add_separator()
        events_context_menu.add_command(label="🗑 Remove Event", command=self.remove_event)

        def show_context_menu(event):
            try:
                events_context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                events_context_menu.grab_release()

        self.events_tree.bind("<Button-3>", show_context_menu)

    def _connect_commands(self):
        """Connect all button commands after UI creation"""
        pass  # Commands are connected inline

    def toggle_monitoring(self):
        """Start/stop system-wide monitoring"""
        from analysis_modules.system_wide_monitor import SystemWideMonitor, EventFilter
        from analysis_modules.sysmon_parser import SysmonLogMonitor

        if not self.monitor_state["monitoring"]:
            # Start monitoring
            try:
                monitor = SystemWideMonitor(max_events=50000)

                # Check Sysmon availability
                sysmon_available = False
                try:
                    sysmon_test = SysmonLogMonitor()
                    sysmon_available = sysmon_test.is_available()
                except:
                    pass

                if sysmon_available:
                    self.sysmon_status.configure(
                        text="✓ Sysmon Enabled (Full monitoring)",
                        text_color="#10b981"
                    )
                else:
                    self.sysmon_status.configure(
                        text="⚠ Sysmon Not Available (Limited monitoring)",
                        text_color="#f59e0b"
                    )

                self.apply_filters()
                monitor.start_monitoring()

                self.app.system_wide_monitor = monitor
                self.monitor_state["monitor"] = monitor
                self.monitor_state["monitoring"] = True
                self.app.system_monitor_active = True

                self.monitor_btn_text.set("⏸ Stop Monitoring")
                self.monitor_btn.configure(fg_color="#059669")
                self.status_label.configure(text="● Monitoring: Active", text_color="#10b981")

                self.refresh_events()

            except Exception as e:
                messagebox.showerror("Error", f"Failed to start monitoring:\n{str(e)}")
                import traceback
                traceback.print_exc()
        else:
            # Stop monitoring
            if self.monitor_state["monitor"]:
                self.monitor_state["monitor"].stop_monitoring()
                self.app.system_wide_monitor = None

            self.monitor_state["monitoring"] = False
            self.monitor_state["monitor"] = None
            self.app.system_monitor_active = False

            self.monitor_btn_text.set("▶ Start Monitoring")
            self.monitor_btn.configure(fg_color=self.colors["red"])
            self.status_label.configure(text="● Monitoring: Stopped", text_color="gray50")
            self.sysmon_status.configure(text="")

            if self.monitor_state["update_job"]:
                self.frame.after_cancel(self.monitor_state["update_job"])
                self.monitor_state["update_job"] = None

    def apply_filters(self):
        """Apply current filter settings"""
        if not self.monitor_state["monitor"]:
            return

        event_filter = self.monitor_state["monitor"].get_filter()

        # PID filter
        pid_text = self.pid_filter_entry.get().strip()
        if pid_text:
            try:
                pid = int(pid_text)
                if self.include_children_var.get():
                    pids_to_filter = self.app.get_child_pids_recursive(pid)
                    pids_to_filter.add(pid)
                    event_filter.set_pid_set(pids_to_filter)
                else:
                    event_filter.set_pid(pid)
            except:
                event_filter.set_pid(None)
        else:
            event_filter.set_pid(None)
            event_filter.set_pid_set(None)

        # Regex filter
        regex_text = self.regex_filter_entry.get().strip()
        if regex_text:
            event_filter.set_path_regex(regex_text)
        else:
            event_filter.set_path_regex(None)

        # Suspicious-only filter
        event_filter.set_suspicious_only(self.suspicious_var.get())

        self.monitor_state["current_filter"] = event_filter
        self._refresh_filtered_events()
        self.update_process_info()

    def _refresh_filtered_events(self):
        """Refresh display with filtered events"""
        self.events_tree.delete(*self.events_tree.get_children())

        monitor = self.monitor_state["monitor"]
        if not monitor:
            return

        event_filter = self.monitor_state["current_filter"]
        all_events = monitor.get_recent_events(count=5000)

        for event in all_events:
            if event_filter and not event_filter.matches(event):
                continue

            is_suspicious = event_filter.is_suspicious(event) if event_filter else False
            tags = ('suspicious',) if is_suspicious else ()

            path = event.get('path', '')
            if len(str(path)) > 100:
                path = str(path)[:97] + "..."

            self.events_tree.insert("", "end", values=(
                event.get('timestamp', ''),
                event.get('pid', 0),
                event.get('process_name', '')[:20],
                event.get('event_type', ''),
                event.get('operation', ''),
                path,
                event.get('result', '')
            ), tags=tags)

    def clear_filters(self):
        """Clear all filters"""
        if not self.monitor_state["monitor"]:
            return

        self.pid_filter_entry.delete(0, tk.END)
        self.regex_filter_entry.delete(0, tk.END)
        self.suspicious_var.set(False)

        for ftype, btn in self.event_type_buttons.items():
            if ftype == "All":
                btn.configure(fg_color=self.colors["red"])
            else:
                btn.configure(fg_color="transparent")

        event_filter = self.monitor_state["monitor"].get_filter()
        event_filter.set_pid(None)
        event_filter.set_path_regex(None)
        event_filter.set_event_types(None)
        event_filter.set_suspicious_only(False)
        self.monitor_state["current_filter"] = event_filter

        self._refresh_filtered_events()
        self.process_info_panel.pack_forget()

    def set_event_type_filter(self, event_type):
        """Set event type filter"""
        for ftype, btn in self.event_type_buttons.items():
            if ftype == event_type:
                btn.configure(fg_color=self.colors["red"])
            else:
                btn.configure(fg_color="transparent")

        if self.monitor_state["monitor"]:
            event_filter = self.monitor_state["monitor"].get_filter()
            if event_type == "All":
                event_filter.set_event_types(None)
            else:
                event_filter.set_event_types([event_type])
            self.monitor_state["current_filter"] = event_filter
            self._refresh_filtered_events()
            self.update_process_info()

    def refresh_events(self):
        """Refresh events display (incremental updates)"""
        if not self.monitor_state["monitoring"] or not self.monitor_state["monitor"]:
            return

        try:
            monitor = self.monitor_state["monitor"]
            new_events = monitor.get_events_since(self.monitor_state["last_update_time"])

            for event in new_events:
                if self.monitor_state["current_filter"] and not self.monitor_state["current_filter"].matches(event):
                    continue

                is_suspicious = False
                if self.monitor_state["current_filter"]:
                    is_suspicious = self.monitor_state["current_filter"].is_suspicious(event)
                tags = ('suspicious',) if is_suspicious else ()

                path = event.get('path', '')
                if len(str(path)) > 100:
                    path = str(path)[:97] + "..."

                self.events_tree.insert("", "end", values=(
                    event.get('timestamp', ''),
                    event.get('pid', 0),
                    event.get('process_name', '')[:20],
                    event.get('event_type', ''),
                    event.get('operation', ''),
                    path,
                    event.get('result', '')
                ), tags=tags)

                self.monitor_state["event_count"] += 1

            # Limit tree size
            children = self.events_tree.get_children()
            if len(children) > 5000:
                for item in children[:len(children) - 5000]:
                    self.events_tree.delete(item)

            # Update statistics
            stats = monitor.get_stats()
            self.stats_label.configure(
                text=f"Total: {stats['total_events']} | "
                     f"File: {stats['file_events']} | "
                     f"Registry: {stats['registry_events']} | "
                     f"Network: {stats['network_events']} | "
                     f"Process: {stats['process_events']} | "
                     f"DNS: {stats.get('dns_events', 0)}"
            )

            self.monitor_state["last_update_time"] = datetime.now()
            self.monitor_state["update_job"] = self.frame.after(500, self.refresh_events)

        except Exception as e:
            print(f"Error refreshing events: {e}")
            import traceback
            traceback.print_exc()

    def update_process_info(self):
        """Update process info panel when PID filter active"""
        pid_text = self.pid_filter_entry.get().strip()

        if pid_text and pid_text.isdigit():
            try:
                import psutil
                pid = int(pid_text)
                proc = psutil.Process(pid)

                info_lines = [f"Process:  {proc.name()}  (PID: {pid})"]

                try:
                    info_lines.append(f"Path:     {proc.exe()}")
                except:
                    info_lines.append("Path:     [Access Denied]")

                try:
                    cmdline = ' '.join(proc.cmdline())
                    if cmdline:
                        info_lines.append(f"Command:  {cmdline[:80]}{'...' if len(cmdline) > 80 else ''}")
                except:
                    pass

                try:
                    parent = proc.parent()
                    if parent:
                        info_lines.append(f"Parent:   {parent.name()} (PID: {parent.pid})")
                except:
                    pass

                self.process_info_label.configure(text="\n".join(info_lines))
                self.process_info_panel.pack(fill="x", pady=(0, 10), before=self._events_frame)

            except Exception:
                self.process_info_label.configure(text=f"Process (PID: {pid_text}) - Not found or access denied")
                self.process_info_panel.pack(fill="x", pady=(0, 10), before=self._events_frame)
        else:
            self.process_info_panel.pack_forget()

    def export_events_to_csv(self):
        """Export events to CSV"""
        if not self.monitor_state["monitor"]:
            messagebox.showwarning("No Data", "No events to export. Start monitoring first.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"mad_system_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )

        if filepath:
            try:
                import csv
                monitor = self.monitor_state["monitor"]
                events = monitor.get_recent_events(count=len(monitor.events))

                with open(filepath, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Timestamp', 'PID', 'Process', 'Event Type',
                                     'Operation', 'Path', 'Result', 'Detail'])

                    for event in events:
                        writer.writerow([
                            event.get('time_full', ''),
                            event.get('pid', ''),
                            event.get('process_name', ''),
                            event.get('event_type', ''),
                            event.get('operation', ''),
                            event.get('path', ''),
                            event.get('result', ''),
                            event.get('detail', '')
                        ])

                messagebox.showinfo("Success", f"Exported {len(events)} events to:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")

    def clear_events_display(self):
        """Clear events display and stats"""
        if self.monitor_state["monitor"]:
            self.monitor_state["monitor"].clear_events()
            self.events_tree.delete(*self.events_tree.get_children())
            self.monitor_state["event_count"] = 0
            self.stats_label.configure(
                text="Total: 0 | File: 0 | Registry: 0 | Network: 0 | Process: 0 | DNS: 0"
            )

    def focus_on_pid(self):
        """Focus monitoring on selected PID"""
        selection = self.events_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an event first")
            return

        item = self.events_tree.item(selection[0])
        pid = item['values'][1]

        self.pid_filter_entry.delete(0, tk.END)
        self.pid_filter_entry.insert(0, str(pid))
        self.apply_filters()
        self.refresh_events()

    def copy_path_to_clipboard(self):
        """Copy event path to clipboard"""
        selection = self.events_tree.selection()
        if not selection:
            return

        item = self.events_tree.item(selection[0])
        path = item['values'][5]

        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(path)
        messagebox.showinfo("Copied", f"Path copied to clipboard:\n{path}")

    def remove_event(self):
        """Remove selected event from display"""
        selection = self.events_tree.selection()
        if selection:
            self.events_tree.delete(selection[0])

    def show(self):
        """Show this subtab"""
        self.frame.pack(fill="both", expand=True)

    def hide(self):
        """Hide this subtab"""
        self.frame.pack_forget()

    def on_show(self):
        """Called when subtab is shown - auto-start monitoring if not active"""
        if not self.monitor_state["monitoring"]:
            print("[GUI] Auto-starting Live Events monitoring...")
            self.toggle_monitoring()
