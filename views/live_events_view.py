"""
Live Events View for MAD - System-wide event monitoring.
Extracted from MAD.py create_live_events_subtab() and related methods.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import threading
from datetime import datetime, timedelta

from typography import Fonts
from views.base_view import BaseView
from analysis_modules.system_wide_monitor import SystemWideMonitor, EventFilter
from analysis_modules.sysmon_parser import SysmonLogMonitor


class LiveEventsView(BaseView):
    """System-wide live event monitoring view."""

    def __init__(self, parent, app, colors):
        super().__init__(parent, app, colors)

        # Event data store: tree item IID -> full event dict
        self._live_event_data = {}

        # Monitoring state
        self.monitor_state = {
            "monitor": None,
            "monitoring": False,
            "current_filter": None,
            "update_job": None,
            "last_update_time": datetime.now() - timedelta(days=1),
            "event_count": 0,
        }

        # Widget references (set during _build)
        self.events_tree = None
        self.toggle_monitoring_btn = None
        self.stats_label = None

        # Filter widgets (set during _build)
        self._monitor_btn_text = None
        self._status_label = None
        self._sysmon_status = None
        self._pid_filter_entry = None
        self._regex_filter_entry = None
        self._suspicious_var = None
        self._include_children_var = None
        self._event_type_buttons = {}
        self._process_info_panel = None
        self._process_info_label = None
        self._events_frame = None

        # Hostname resolution cache
        self._hostname_cache = {}

        self._build()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build(self):
        """Build the Live Events UI."""
        frame = self.frame

        # Main content area
        content = ctk.CTkFrame(frame, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=(0, 5))

        # ===== CONTROL PANEL =====
        control_panel = ctk.CTkFrame(content, fg_color=self.colors["navy"])
        control_panel.pack(fill="x", pady=(0, 5))

        # Row 1: Start/Stop and Status
        row1 = ctk.CTkFrame(control_panel, fg_color="transparent")
        row1.pack(fill="x", padx=10, pady=(5, 3))

        # Start/Stop button
        self._monitor_btn_text = tk.StringVar(value="\u25b6 Start Monitoring")
        self.toggle_monitoring_btn = ctk.CTkButton(
            row1,
            textvariable=self._monitor_btn_text,
            command=self.toggle_monitoring,
            height=40,
            width=180,
            font=Fonts.label_large,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
        )
        self.toggle_monitoring_btn.pack(side="left", padx=(0, 20))

        # Status label
        self._status_label = ctk.CTkLabel(
            row1,
            text="\u25cf Monitoring: Stopped",
            font=Fonts.body_large,
            text_color="gray50",
        )
        self._status_label.pack(side="left", padx=10)

        # Sysmon status
        self._sysmon_status = ctk.CTkLabel(
            row1,
            text="",
            font=Fonts.helper,
            text_color="gray60",
        )
        self._sysmon_status.pack(side="left", padx=10)

        # Export and Clear buttons
        export_btn = ctk.CTkButton(
            row1,
            text="\U0001f4be Export CSV",
            command=self.export_events_to_csv,
            height=35,
            width=120,
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["red"],
        )
        export_btn.pack(side="right", padx=5)

        clear_btn = ctk.CTkButton(
            row1,
            text="\U0001f5d1 Clear Events",
            command=self.clear_events_display,
            height=35,
            width=120,
            fg_color="transparent",
            border_width=2,
            border_color=self.colors["red"],
        )
        clear_btn.pack(side="right", padx=5)

        # Row 2: Statistics
        row2 = ctk.CTkFrame(control_panel, fg_color="transparent")
        row2.pack(fill="x", padx=10, pady=(0, 5))

        self.stats_label = ctk.CTkLabel(
            row2,
            text="Total: 0 | File: 0 | Registry: 0 | Network: 0 | Process: 0 | DNS: 0 | Persistence: 0",
            font=Fonts.body,
            text_color="gray60",
        )
        self.stats_label.pack(side="left")

        # ===== FILTER PANEL =====
        filter_panel = ctk.CTkFrame(content, fg_color=self.colors["navy"])
        filter_panel.pack(fill="x", pady=(0, 5))

        # Filter row 1: Event types
        filter_row1 = ctk.CTkFrame(filter_panel, fg_color="transparent")
        filter_row1.pack(fill="x", padx=10, pady=(5, 3))

        filter_label1 = ctk.CTkLabel(
            filter_row1,
            text="Event Type:",
            font=Fonts.body_bold,
        )
        filter_label1.pack(side="left", padx=(0, 10))

        # Event type filter buttons
        filter_types = ["All", "File", "Registry", "Network", "Process", "Thread", "DNS", "Persistence"]
        self._event_type_buttons = {}

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
                border_color=self.colors["red"],
            )
            btn.pack(side="left", padx=3)
            self._event_type_buttons[ftype] = btn

        # Suspicious only toggle
        self._suspicious_var = tk.BooleanVar(value=False)
        suspicious_check = ctk.CTkCheckBox(
            filter_row1,
            text="\U0001f6a8 Suspicious Only",
            variable=self._suspicious_var,
            command=lambda: self.apply_filters() if self.monitor_state["monitoring"] else None,
            font=Fonts.body_bold,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
        )
        suspicious_check.pack(side="right", padx=10)

        # Filter row 2: PID and regex
        filter_row2 = ctk.CTkFrame(filter_panel, fg_color="transparent")
        filter_row2.pack(fill="x", padx=10, pady=(3, 5))

        # PID filter
        pid_filter_label = ctk.CTkLabel(
            filter_row2,
            text="PID Filter:",
            font=Fonts.helper,
        )
        pid_filter_label.pack(side="left", padx=(0, 5))

        self._pid_filter_entry = ctk.CTkEntry(
            filter_row2,
            placeholder_text="Enter PID (optional)",
            width=150,
            height=30,
        )
        self._pid_filter_entry.pack(side="left", padx=5)

        # Include child processes checkbox
        self._include_children_var = tk.BooleanVar(value=False)
        include_children_checkbox = ctk.CTkCheckBox(
            filter_row2,
            text="Include children",
            variable=self._include_children_var,
            font=Fonts.helper,
            width=120,
        )
        include_children_checkbox.pack(side="left", padx=5)

        # Path regex filter
        regex_filter_label = ctk.CTkLabel(
            filter_row2,
            text="Path Regex:",
            font=Fonts.helper,
        )
        regex_filter_label.pack(side="left", padx=(20, 5))

        self._regex_filter_entry = ctk.CTkEntry(
            filter_row2,
            placeholder_text="Enter regex pattern (e.g., .*\\Run\\.*)",
            width=300,
            height=30,
        )
        self._regex_filter_entry.pack(side="left", padx=5)

        apply_filter_btn = ctk.CTkButton(
            filter_row2,
            text="Apply Filters",
            command=self.apply_filters,
            height=30,
            width=100,
            fg_color=self.colors["red"],
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
            border_color=self.colors["red"],
        )
        clear_filter_btn.pack(side="left", padx=5)

        # ===== PROCESS INFO PANEL (Procmon-style, shown when PID filter active) =====
        self._process_info_panel = ctk.CTkFrame(content, fg_color=self.colors["dark_blue"], height=80)
        self._process_info_label = ctk.CTkLabel(
            self._process_info_panel,
            text="",
            font=Fonts.helper,
            text_color="white",
            anchor="w",
            justify="left",
        )
        self._process_info_label.pack(fill="both", expand=True, padx=15, pady=10)

        # ===== EVENTS DISPLAY =====
        self._events_frame = ctk.CTkFrame(content, fg_color="gray20")
        self._events_frame.pack(fill="both", expand=True)

        # Scrollbars
        events_vsb = tk.Scrollbar(self._events_frame, orient="vertical", bg="#1a1a1a")
        events_vsb.pack(side="right", fill="y")

        events_hsb = tk.Scrollbar(self._events_frame, orient="horizontal", bg="#1a1a1a")
        events_hsb.pack(side="bottom", fill="x")

        # Style the Live Events tree with slightly larger font
        _le_font_size = 13 if self.is_large_screen else 11
        _le_heading_size = 14 if self.is_large_screen else 12
        _le_row_height = 28 if self.is_large_screen else 22

        style = ttk.Style()
        style.configure(
            "LiveEvents.Treeview",
            background="#1a1a1a",
            foreground="white",
            fieldbackground="#1a1a1a",
            borderwidth=0,
            font=("Segoe UI", _le_font_size),
            rowheight=_le_row_height,
        )
        style.configure(
            "LiveEvents.Treeview.Heading",
            background="#0d1520",
            foreground="white",
            borderwidth=1,
            font=("Segoe UI", _le_heading_size, "bold"),
        )
        style.map("LiveEvents.Treeview", background=[("selected", "#dc2626")])

        # TreeView for events
        columns = ("time", "pid", "process", "type", "operation", "path", "result")
        self.events_tree = ttk.Treeview(
            self._events_frame,
            columns=columns,
            show="headings",
            height=25,
            yscrollcommand=events_vsb.set,
            xscrollcommand=events_hsb.set,
            style="LiveEvents.Treeview",
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
        self.events_tree.column("process", width=130, minwidth=100)
        self.events_tree.column("type", width=85, minwidth=80)
        self.events_tree.column("operation", width=160, minwidth=120)
        self.events_tree.column("path", width=400, minwidth=200)
        self.events_tree.column("result", width=100, minwidth=80)

        # Tag for suspicious events
        self.events_tree.tag_configure("suspicious", background="#5c1c1c", foreground="#ff6b6b")
        # Tag for Sigma rule matches (higher priority - purple/magenta)
        self.events_tree.tag_configure("sigma_match", background="#4c1d95", foreground="#c084fc")
        # Tag for persistence changes (orange)
        self.events_tree.tag_configure("persistence", background="#78350f", foreground="#fbbf24")

        self.events_tree.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        events_vsb.config(command=self.events_tree.yview)
        events_hsb.config(command=self.events_tree.xview)

        # Context menu for events
        self._events_context_menu = tk.Menu(
            self.events_tree, tearoff=0, bg="#1a1a1a", fg="white",
            activebackground=self.colors["red"],
        )
        self._events_context_menu.add_command(label="\U0001f50d Focus on PID", command=self.focus_on_pid)
        self._events_context_menu.add_command(label="\U0001f4cb Copy Path", command=self.copy_path_to_clipboard)
        self._events_context_menu.add_separator()
        self._events_context_menu.add_command(
            label="\u2795 Extract IOCs to Case",
            command=lambda: self.add_live_event_iocs_to_case(self.events_tree),
        )
        self._events_context_menu.add_separator()
        self._events_context_menu.add_command(label="\U0001f5d1 Remove Event", command=self.remove_event)

        self.events_tree.bind("<Button-3>", self._show_context_menu)
        self.events_tree.bind("<Double-1>", lambda e: self._show_live_event_detail())

    # ------------------------------------------------------------------
    # Context menu
    # ------------------------------------------------------------------

    def _show_context_menu(self, event):
        """Show right-click context menu on the events tree."""
        try:
            self._events_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._events_context_menu.grab_release()

    # ------------------------------------------------------------------
    # Monitoring start / stop
    # ------------------------------------------------------------------

    def toggle_monitoring(self):
        """Start/stop system-wide monitoring."""
        if not self.monitor_state["monitoring"]:
            # Start monitoring
            try:
                # Create system-wide monitor (with Sigma rules if enabled)
                sigma_path = self.app.sigma_rules_path if self.app.sigma_enabled else None
                monitor = SystemWideMonitor(max_events=50000, sigma_rules_path=sigma_path)

                # Register Sigma match callback for GUI alerts
                if monitor.is_sigma_enabled():
                    monitor.register_sigma_callback(self.app.on_sigma_match_detected)

                # Check if Sysmon is available
                sysmon_available = False
                try:
                    sysmon_test = SysmonLogMonitor()
                    sysmon_available = sysmon_test.is_available()
                except:
                    pass

                sigma_info = ""
                if monitor.is_sigma_enabled():
                    sigma_count = monitor.get_sigma_evaluator().get_rule_count()
                    sigma_info = f" | Sigma: {sigma_count} rules"

                if sysmon_available:
                    self._sysmon_status.configure(
                        text=f"\u2713 Sysmon Enabled (Full monitoring){sigma_info}",
                        text_color="#10b981",
                    )
                else:
                    self._sysmon_status.configure(
                        text=f"\u26a0 Sysmon Not Available (Limited monitoring){sigma_info}",
                        text_color="#f59e0b",
                    )

                # Apply current filters
                self.apply_filters()

                # Start monitoring
                monitor.start_monitoring()

                self.app.system_wide_monitor = monitor
                self.monitor_state["monitor"] = monitor
                self.monitor_state["monitoring"] = True
                self.app.system_monitor_active = True

                # Also start persistence monitoring (feeds into Live Events)
                if not self.app.persistence_monitor_active:
                    self.app.persistence_monitor.start_monitoring()
                    self.app.persistence_monitor_active = True

                self._monitor_btn_text.set("\u23f8 Stop Monitoring")
                self.toggle_monitoring_btn.configure(fg_color="#059669")  # Green
                self._status_label.configure(text="\u25cf Monitoring: Active", text_color="#10b981")

                # Start auto-refresh
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

            # Also stop persistence monitoring
            if self.app.persistence_monitor_active:
                self.app.persistence_monitor.stop_monitoring()
                self.app.persistence_monitor_active = False

            self.monitor_state["monitoring"] = False
            self.monitor_state["monitor"] = None
            self.app.system_monitor_active = False

            self._monitor_btn_text.set("\u25b6 Start Monitoring")
            self.toggle_monitoring_btn.configure(fg_color=self.colors["red"])
            self._status_label.configure(text="\u25cf Monitoring: Stopped", text_color="gray50")
            self._sysmon_status.configure(text="")

            # Cancel auto-refresh
            if self.monitor_state["update_job"]:
                self.frame.after_cancel(self.monitor_state["update_job"])
                self.monitor_state["update_job"] = None

    # ------------------------------------------------------------------
    # Filter logic
    # ------------------------------------------------------------------

    def apply_filters(self):
        """Apply current filter settings to the monitor."""
        if not self.monitor_state["monitor"]:
            return

        event_filter = self.monitor_state["monitor"].get_filter()

        # Apply PID filter (with optional child processes)
        pid_text = self._pid_filter_entry.get().strip()
        if pid_text:
            try:
                pid = int(pid_text)

                # Check if we should include child processes
                if self._include_children_var.get():
                    # Get all child PIDs recursively
                    pids_to_filter = self.app.get_child_pids_recursive(pid)
                    pids_to_filter.add(pid)  # Include the parent PID too
                    event_filter.set_pid_set(pids_to_filter)
                else:
                    # Just filter by the single PID
                    event_filter.set_pid(pid)
            except:
                event_filter.set_pid(None)
        else:
            event_filter.set_pid(None)
            event_filter.set_pid_set(None)

        # Apply regex filter
        regex_text = self._regex_filter_entry.get().strip()
        if regex_text:
            event_filter.set_path_regex(regex_text)
        else:
            event_filter.set_path_regex(None)

        # Apply suspicious-only filter
        event_filter.set_suspicious_only(self._suspicious_var.get())

        self.monitor_state["current_filter"] = event_filter

        # Clear and refresh display with filtered events
        self.events_tree.delete(*self.events_tree.get_children())
        self._live_event_data.clear()

        # Get ALL events from monitor and filter them for display
        monitor = self.monitor_state["monitor"]
        all_events = monitor.get_recent_events(count=5000)  # Get last 5000 events

        for event in all_events:
            # Apply current filter
            if not event_filter.matches(event):
                continue

            # Determine row highlighting
            has_sigma = bool(event.get("sigma_matches"))
            is_persistence = event.get("event_type") == "Persistence"
            is_suspicious = event_filter.is_suspicious(event)
            if has_sigma:
                tags = ("sigma_match",)
            elif is_persistence:
                tags = ("persistence",)
            elif is_suspicious:
                tags = ("suspicious",)
            else:
                tags = ()

            # Truncate long paths
            path = event.get("path", "")
            if len(str(path)) > 100:
                path = str(path)[:97] + "..."

            # Insert event
            iid = self.events_tree.insert(
                "", "end",
                values=(
                    event.get("timestamp", ""),
                    event.get("pid", 0),
                    event.get("process_name", "")[:20],
                    event.get("event_type", ""),
                    event.get("operation", ""),
                    path,
                    event.get("result", ""),
                ),
                tags=tags,
            )
            self._live_event_data[iid] = event

        # Update process info panel
        self.update_process_info()

    def clear_filters(self):
        """Clear all filters and show full event list."""
        if not self.monitor_state["monitor"]:
            return

        # Clear filter inputs
        self._pid_filter_entry.delete(0, tk.END)
        self._regex_filter_entry.delete(0, tk.END)
        self._suspicious_var.set(False)

        # Reset event type to "All"
        for ftype, btn in self._event_type_buttons.items():
            if ftype == "All":
                btn.configure(fg_color=self.colors["red"])
            else:
                btn.configure(fg_color="transparent")

        # Reset filter in monitor
        event_filter = self.monitor_state["monitor"].get_filter()
        event_filter.set_pid(None)
        event_filter.set_path_regex(None)
        event_filter.set_event_types(None)
        event_filter.set_suspicious_only(False)
        self.monitor_state["current_filter"] = event_filter

        # Clear and refresh display with ALL events
        self.events_tree.delete(*self.events_tree.get_children())
        self._live_event_data.clear()

        monitor = self.monitor_state["monitor"]
        all_events = monitor.get_recent_events(count=5000)

        for event in all_events:
            # Determine row highlighting
            has_sigma = bool(event.get("sigma_matches"))
            is_persistence = event.get("event_type") == "Persistence"
            is_suspicious = event_filter.is_suspicious(event)
            if has_sigma:
                tags = ("sigma_match",)
            elif is_persistence:
                tags = ("persistence",)
            elif is_suspicious:
                tags = ("suspicious",)
            else:
                tags = ()

            # Truncate long paths
            path = event.get("path", "")
            if len(str(path)) > 100:
                path = str(path)[:97] + "..."

            # Insert event
            iid = self.events_tree.insert(
                "", "end",
                values=(
                    event.get("timestamp", ""),
                    event.get("pid", 0),
                    event.get("process_name", "")[:20],
                    event.get("event_type", ""),
                    event.get("operation", ""),
                    path,
                    event.get("result", ""),
                ),
                tags=tags,
            )
            self._live_event_data[iid] = event

        # Hide process info panel
        self._process_info_panel.pack_forget()

    def update_process_info(self):
        """Update process info panel (Procmon-style) when PID filter is active."""
        pid_text = self._pid_filter_entry.get().strip()

        if pid_text and pid_text.isdigit():
            try:
                pid = int(pid_text)
                # Get process info using psutil
                import psutil
                proc = psutil.Process(pid)

                # Build Procmon-style info string
                info_lines = []
                info_lines.append(f"Process:  {proc.name()}  (PID: {pid})")

                try:
                    info_lines.append(f"Path:     {proc.exe()}")
                except:
                    info_lines.append(f"Path:     [Access Denied]")

                try:
                    cmdline = " ".join(proc.cmdline())
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

                self._process_info_label.configure(text="\n".join(info_lines))
                self._process_info_panel.pack(fill="x", pady=(0, 10), before=self._events_frame)

            except Exception:
                self._process_info_label.configure(text=f"Process (PID: {pid}) - Not found or access denied")
                self._process_info_panel.pack(fill="x", pady=(0, 10), before=self._events_frame)
        else:
            # No PID filter active, hide panel
            self._process_info_panel.pack_forget()

    def set_event_type_filter(self, event_type):
        """Set event type filter."""
        # Update button colors
        for ftype, btn in self._event_type_buttons.items():
            if ftype == event_type:
                btn.configure(fg_color=self.colors["red"])
            else:
                btn.configure(fg_color="transparent")

        # Apply filter
        if self.monitor_state["monitor"]:
            event_filter = self.monitor_state["monitor"].get_filter()
            if event_type == "All":
                event_filter.set_event_types(None)
            else:
                event_filter.set_event_types([event_type])

            self.monitor_state["current_filter"] = event_filter

            # Clear and refresh display with filtered events
            self.events_tree.delete(*self.events_tree.get_children())
            self._live_event_data.clear()

            # Get ALL events from monitor and filter them for display
            monitor = self.monitor_state["monitor"]
            all_events = monitor.get_recent_events(count=5000)

            for event in all_events:
                # Apply current filter
                if not event_filter.matches(event):
                    continue

                # Determine row highlighting
                has_sigma = bool(event.get("sigma_matches"))
                is_persistence = event.get("event_type") == "Persistence"
                is_suspicious = event_filter.is_suspicious(event)
                if has_sigma:
                    tags = ("sigma_match",)
                elif is_persistence:
                    tags = ("persistence",)
                elif is_suspicious:
                    tags = ("suspicious",)
                else:
                    tags = ()

                # Truncate long paths
                path = event.get("path", "")
                if len(str(path)) > 100:
                    path = str(path)[:97] + "..."

                # Insert event
                iid = self.events_tree.insert(
                    "", "end",
                    values=(
                        event.get("timestamp", ""),
                        event.get("pid", 0),
                        event.get("process_name", "")[:20],
                        event.get("event_type", ""),
                        event.get("operation", ""),
                        path,
                        event.get("result", ""),
                    ),
                    tags=tags,
                )
                self._live_event_data[iid] = event

            # Update process info panel
            self.update_process_info()

    # ------------------------------------------------------------------
    # Event refresh (auto-refresh loop)
    # ------------------------------------------------------------------

    def refresh_events(self):
        """Refresh the events display (incremental updates)."""
        if not self.monitor_state["monitoring"] or not self.monitor_state["monitor"]:
            return

        try:
            monitor = self.monitor_state["monitor"]

            # Get events since last update (incremental)
            new_events = monitor.get_events_since(self.monitor_state["last_update_time"])

            # Add only new events to tree (incremental update for performance)
            for event in new_events:
                # Apply current filter to new events
                if self.monitor_state["current_filter"] and not self.monitor_state["current_filter"].matches(event):
                    continue

                # Determine row highlighting
                has_sigma = bool(event.get("sigma_matches"))
                is_persistence = event.get("event_type") == "Persistence"
                is_suspicious = False
                if self.monitor_state["current_filter"]:
                    is_suspicious = self.monitor_state["current_filter"].is_suspicious(event)
                if has_sigma:
                    tags = ("sigma_match",)
                elif is_persistence:
                    tags = ("persistence",)
                elif is_suspicious:
                    tags = ("suspicious",)
                else:
                    tags = ()

                # Truncate long paths
                path = event.get("path", "")
                if len(str(path)) > 100:
                    path = str(path)[:97] + "..."

                # Insert event
                iid = self.events_tree.insert(
                    "", "end",
                    values=(
                        event.get("timestamp", ""),
                        event.get("pid", 0),
                        event.get("process_name", "")[:20],
                        event.get("event_type", ""),
                        event.get("operation", ""),
                        path,
                        event.get("result", ""),
                    ),
                    tags=tags,
                )
                self._live_event_data[iid] = event

                self.monitor_state["event_count"] += 1

            # Limit tree size for performance (keep last 5000 events)
            children = self.events_tree.get_children()
            if len(children) > 5000:
                for item in children[: len(children) - 5000]:
                    self._live_event_data.pop(item, None)
                    self.events_tree.delete(item)

            # Update statistics
            stats = monitor.get_stats()
            sigma_count = stats.get("sigma_matches", 0)
            persist_count = stats.get("persistence_events", 0)
            sigma_text = f" | Sigma: {sigma_count}" if sigma_count > 0 else ""
            persist_text = f" | Persist: {persist_count}" if persist_count > 0 else ""
            self.stats_label.configure(
                text=f"Total: {stats['total_events']} | "
                     f"File: {stats['file_events']} | "
                     f"Registry: {stats['registry_events']} | "
                     f"Network: {stats['network_events']} | "
                     f"Process: {stats['process_events']} | "
                     f"DNS: {stats.get('dns_events', 0)}"
                     f"{persist_text}{sigma_text}"
            )

            # Update last update time
            self.monitor_state["last_update_time"] = datetime.now()

            # Schedule next refresh (500ms)
            self.monitor_state["update_job"] = self.frame.after(500, self.refresh_events)

        except Exception as e:
            print(f"Error refreshing events: {e}")
            import traceback
            traceback.print_exc()

    # ------------------------------------------------------------------
    # Export / clear
    # ------------------------------------------------------------------

    def export_events_to_csv(self):
        """Export events to CSV."""
        if not self.monitor_state["monitor"]:
            messagebox.showwarning("No Data", "No events to export. Start monitoring first.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"mad_system_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        )

        if filepath:
            try:
                import csv
                monitor = self.monitor_state["monitor"]
                events = monitor.get_recent_events(count=len(monitor.events))

                with open(filepath, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        "Timestamp", "PID", "Process", "Event Type",
                        "Operation", "Path", "Result", "Detail",
                    ])

                    for event in events:
                        writer.writerow([
                            event.get("time_full", ""),
                            event.get("pid", ""),
                            event.get("process_name", ""),
                            event.get("event_type", ""),
                            event.get("operation", ""),
                            event.get("path", ""),
                            event.get("result", ""),
                            event.get("detail", ""),
                        ])

                messagebox.showinfo("Success", f"Exported {len(events)} events to:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")

    def clear_events_display(self):
        """Clear events display and stats."""
        if self.monitor_state["monitor"]:
            self.monitor_state["monitor"].clear_events()
            self.events_tree.delete(*self.events_tree.get_children())
            self.monitor_state["event_count"] = 0
            self.stats_label.configure(
                text="Total: 0 | File: 0 | Registry: 0 | Network: 0 | Process: 0 | DNS: 0"
            )

    # ------------------------------------------------------------------
    # Context menu actions
    # ------------------------------------------------------------------

    def focus_on_pid(self):
        """Focus monitoring on selected PID."""
        selection = self.events_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select an event first")
            return

        item = self.events_tree.item(selection[0])
        pid = item["values"][1]  # PID column

        self._pid_filter_entry.delete(0, tk.END)
        self._pid_filter_entry.insert(0, str(pid))
        self.apply_filters()
        self.refresh_events()

    def copy_path_to_clipboard(self):
        """Copy event path to clipboard."""
        selection = self.events_tree.selection()
        if not selection:
            return

        item = self.events_tree.item(selection[0])
        path = item["values"][5]  # Path column

        self.root.clipboard_clear()
        self.root.clipboard_append(path)
        messagebox.showinfo("Copied", f"Path copied to clipboard:\n{path}")

    def remove_event(self):
        """Remove selected event from display."""
        selection = self.events_tree.selection()
        if selection:
            self.events_tree.delete(selection[0])

    # ------------------------------------------------------------------
    # Event detail popup
    # ------------------------------------------------------------------

    def _show_live_event_detail(self):
        """Show full details for a double-clicked live event."""
        sel = self.events_tree.selection()
        if not sel:
            return
        iid = sel[0]
        event = self._live_event_data.get(iid)
        if not event:
            return

        detail = ctk.CTkToplevel(self.root)
        detail.title(f"Event Detail: {event.get('operation', '')} - PID {event.get('pid', '')}")
        detail.geometry("720x500")
        detail.configure(fg_color="#1a1a1a")
        detail.attributes("-topmost", True)
        detail.after(200, lambda: detail.focus_force())

        # Header with event type coloring
        etype = event.get("event_type", "Unknown")
        type_colors = {
            "Process": "#22d3ee",
            "Registry": "#f97316",
            "File": "#4ade80",
            "Network": "#a78bfa",
            "DNS": "#fbbf24",
            "ImageLoad": "#f472b6",
            "Persistence": "#fbbf24",
        }
        header_color = type_colors.get(etype, "#9ca3af")

        ctk.CTkLabel(
            detail,
            text=f"{etype}  |  {event.get('operation', '')}",
            font=Fonts.title_medium,
            text_color=header_color,
        ).pack(pady=(15, 5), padx=15, anchor="w")

        # Sigma match banner
        sigma = event.get("sigma_matches")
        if sigma:
            sigma_text = "  |  ".join(sigma) if isinstance(sigma, list) else str(sigma)
            ctk.CTkLabel(
                detail,
                text=f"SIGMA: {sigma_text}",
                font=Fonts.body_bold,
                text_color="#c084fc",
                fg_color="#4c1d95",
                corner_radius=6,
            ).pack(padx=15, pady=(0, 5), anchor="w")

        # Build detail text
        lines = [
            f"Time:       {event.get('timestamp', '')}",
            f"PID:        {event.get('pid', '')}",
            f"Process:    {event.get('process_name', '')}",
            f"User:       {event.get('user', 'N/A')}",
            f"Event Type: {etype}",
            f"Operation:  {event.get('operation', '')}",
            f"Result:     {event.get('result', '')}",
            f"Event ID:   {event.get('event_id', 'N/A')}",
            "",
            "Path / Target:",
            "=" * 60,
            str(event.get("path", "")),
        ]

        # Network events: resolve hostname for the remote IP
        if etype == "Network":
            remote_path = str(event.get("path", ""))
            if remote_path and ":" in remote_path:
                remote_ip = remote_path.split(":")[0]
                hostname = self._resolve_hostname(remote_ip)
                if hostname and hostname != "-":
                    lines.append(f"Hostname:   {hostname}")

        detail_field = event.get("detail", "")
        if detail_field:
            lines += ["", "Detail / Command Line:", "=" * 60, str(detail_field)]

        # Persistence events: show entry-specific detail
        persist_entry = event.get("persistence_entry")
        if persist_entry and isinstance(persist_entry, dict):
            lines += [
                "",
                "Persistence Entry:",
                "=" * 60,
                f"  Type:     {persist_entry.get('entry_type', '')}",
                f"  Source:   {persist_entry.get('source', '')}",
                f"  Location: {persist_entry.get('location', '')}",
                f"  Name:     {persist_entry.get('name', '')}",
                f"  Severity: {persist_entry.get('severity', '').upper()}",
                f"  Value:    {persist_entry.get('value', '')}",
            ]
            prev = persist_entry.get("extra", {}).get("previous_value")
            if prev:
                lines.append(f"  Previous: {prev}")

        # Show any extra raw fields
        skip_keys = {
            "timestamp", "time_full", "event_type", "operation", "path",
            "result", "detail", "pid", "tid", "process_name", "user",
            "event_id", "sigma_matches", "persistence_entry",
            "persistence_change_type",
        }
        extra = {k: v for k, v in event.items() if k not in skip_keys and v}
        if extra:
            lines += ["", "Additional Fields:", "=" * 60]
            for k, v in extra.items():
                lines.append(f"  {k}: {v}")

        text_widget = ctk.CTkTextbox(
            detail, font=Fonts.body, fg_color="#0d1520",
            text_color="white", wrap="word",
        )
        text_widget.pack(fill="both", expand=True, padx=15, pady=10)
        text_widget.insert("1.0", "\n".join(lines))
        text_widget.configure(state="disabled")

        btn_frame = ctk.CTkFrame(detail, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=(0, 15))

        # Copy detail/command
        copy_text = str(detail_field) if detail_field else str(event.get("path", ""))
        ctk.CTkButton(
            btn_frame, text="\U0001f4cb Copy Detail", height=32, width=140,
            fg_color=self.colors["navy"], hover_color=self.colors["dark_blue"],
            command=lambda: (self.root.clipboard_clear(), self.root.clipboard_append(copy_text)),
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame, text="\U0001f4cb Copy Path", height=32, width=140,
            fg_color=self.colors["navy"], hover_color=self.colors["dark_blue"],
            command=lambda: (
                self.root.clipboard_clear(),
                self.root.clipboard_append(str(event.get("path", ""))),
            ),
        ).pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame, text="Close", command=detail.destroy,
            fg_color=self.colors["red"], hover_color=self.colors["red_dark"],
            height=32, width=100,
        ).pack(side="right", padx=5)

    # ------------------------------------------------------------------
    # Persistence integration (injected into Live Events timeline)
    # ------------------------------------------------------------------

    def on_persistence_change_detected(self, change_type, entry):
        """Callback fired from PersistenceMonitor when a change is found.

        Injects the change into the Live Events timeline as a Persistence
        event and shows a popup alert for high/critical severity changes.
        """
        self.app.persistence_change_count += 1
        # Inject as a Live Events event via the system-wide monitor
        self.root.after(0, lambda: self._inject_persistence_event(change_type, entry))
        # Show alert popup for high/critical changes
        if entry.severity in ("high", "critical"):
            self.root.after(0, lambda: self._show_persistence_alert(change_type, entry))

    def _inject_persistence_event(self, change_type, entry):
        """Push a persistence change into the Live Events timeline."""
        if self.app.system_wide_monitor is None:
            return
        now = datetime.now()
        severity_tag = f"[{entry.severity.upper()}]"
        operation = f"Persistence{change_type.capitalize()}"  # PersistenceAdded / PersistenceRemoved / PersistenceModified
        detail_parts = [f"Name: {entry.name}", f"Value: {entry.value[:200]}"]
        if entry.extra.get("previous_value"):
            detail_parts.append(f"Previous: {entry.extra['previous_value'][:200]}")
        event = {
            "timestamp": now.strftime("%H:%M:%S.%f")[:-3],
            "time_full": now.isoformat(),
            "event_type": "Persistence",
            "operation": operation,
            "path": entry.source,
            "result": f"{severity_tag} {change_type.upper()}",
            "detail": " | ".join(detail_parts),
            "pid": 0,
            "tid": 0,
            "process_name": "PersistenceMonitor",
            # Extra fields for the detail popup
            "persistence_entry": entry.to_dict(),
            "persistence_change_type": change_type,
        }
        self.app.system_wide_monitor._add_event(event)

    def _show_persistence_alert(self, change_type, entry):
        """Show a popup alert for a significant persistence change."""
        alert = ctk.CTkToplevel(self.root)
        alert.title("Persistence Change Detected")
        alert.geometry("520x300")
        alert.configure(fg_color="#1a1a1a")
        alert.attributes("-topmost", True)
        alert.after(200, lambda: alert.focus_force())

        severity_colors = {
            "critical": "#ef4444",
            "high": "#f97316",
            "medium": "#eab308",
            "low": "#9ca3af",
        }
        header_color = severity_colors.get(entry.severity, "#9ca3af")

        ctk.CTkLabel(
            alert,
            text=f"{change_type.upper()}: {entry.entry_type.replace('_', ' ').title()}",
            font=Fonts.title_medium,
            text_color=header_color,
        ).pack(pady=(15, 5), padx=15, anchor="w")

        details = (
            f"Source:   {entry.source}\n"
            f"Name:     {entry.name}\n"
            f"Value:    {entry.value[:300]}\n"
            f"Severity: {entry.severity.upper()}"
        )
        if entry.extra.get("previous_value"):
            details += f"\nPrevious: {entry.extra['previous_value'][:200]}"

        text_widget = ctk.CTkTextbox(
            alert, font=Fonts.body, fg_color="#0d1520",
            text_color="white", wrap="word",
        )
        text_widget.pack(fill="both", expand=True, padx=15, pady=10)
        text_widget.insert("1.0", details)
        text_widget.configure(state="disabled")

        ctk.CTkButton(
            alert, text="Dismiss", command=alert.destroy,
            fg_color=self.colors["red"], hover_color=self.colors["red_dark"],
            height=32, width=100,
        ).pack(pady=(0, 15))

    # ------------------------------------------------------------------
    # IOC extraction
    # ------------------------------------------------------------------

    def add_live_event_iocs_to_case(self, events_tree):
        """Extract and add IOCs from selected live event(s) to current case."""
        if not self.app.current_case:
            messagebox.showwarning(
                "No Active Case",
                "No active case to add IOCs to. Please create or load a case first.",
            )
            return

        selections = events_tree.selection()
        if not selections:
            messagebox.showwarning("No Selection", "Please select one or more live events first.")
            return

        try:
            # Collect all text from selected events to extract IOCs
            all_text = []
            for selection in selections:
                item = events_tree.item(selection)
                values = item["values"]  # [time, pid, process, type, operation, path, result]

                # Get path/target field (index 5) which is most likely to contain IOCs
                if len(values) > 5:
                    path = str(values[5])
                    all_text.append(path)

            # Join all text and extract IOCs using case_manager's built-in method
            combined_text = " ".join(all_text)
            extracted_iocs = self.app.case_manager.extract_iocs_from_text(combined_text)

            # Add extracted IOCs to case
            total_added = 0
            for ioc_type in ["urls", "ips", "domains"]:
                if extracted_iocs.get(ioc_type):
                    for ioc_value in extracted_iocs[ioc_type]:
                        self.app.case_manager.add_ioc(ioc_type, ioc_value)
                        total_added += 1

            if total_added > 0:
                self.app.refresh_iocs_display()
                ioc_summary = (
                    f"URLs: {len(extracted_iocs.get('urls', []))}, "
                    f"IPs: {len(extracted_iocs.get('ips', []))}, "
                    f"Domains: {len(extracted_iocs.get('domains', []))}"
                )
                messagebox.showinfo(
                    "Success",
                    f"Extracted and added {total_added} IOC(s) to case!\n\n{ioc_summary}",
                )
            else:
                messagebox.showinfo(
                    "No IOCs Found",
                    "No IOCs (URLs, IPs, or domains) were found in the selected event(s).",
                )

        except Exception as e:
            messagebox.showerror("Error", f"Failed to extract IOCs: {str(e)}")

    # ------------------------------------------------------------------
    # Hostname resolution (local cache)
    # ------------------------------------------------------------------

    def _resolve_hostname(self, ip_address):
        """Resolve IP address to hostname with caching."""
        # Check cache first
        if ip_address in self._hostname_cache:
            return self._hostname_cache[ip_address]

        # Skip resolution for local/private IPs
        if ip_address in ("", "0.0.0.0", "127.0.0.1", "localhost", "*"):
            self._hostname_cache[ip_address] = "-"
            return "-"

        # Try to resolve
        try:
            import socket
            hostname = socket.gethostbyaddr(ip_address)[0]
            self._hostname_cache[ip_address] = hostname
            return hostname
        except:
            # If resolution fails, just use the IP
            self._hostname_cache[ip_address] = "-"
            return "-"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def destroy(self):
        """Clean up resources when view is destroyed."""
        # Cancel any pending auto-refresh job
        if self.monitor_state["update_job"]:
            self.frame.after_cancel(self.monitor_state["update_job"])
            self.monitor_state["update_job"] = None
        super().destroy()
