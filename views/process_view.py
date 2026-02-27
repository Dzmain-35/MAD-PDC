"""
Process View for MAD - Process tree, HTTP traffic panel, and all process analysis.
Extracted from MAD.py create_processes_subtab() and related methods.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import socket
import threading
import platform
import subprocess
import shutil

from typography import Fonts
from views.base_view import BaseView
from views.string_analysis_view import StringAnalysisPanel
from analysis_modules.procmon_events import ProcmonLiveMonitor, ProcmonEvent


class ProcessView(BaseView):
    """Process tree view with HTTP traffic panel and all process analysis methods."""

    def __init__(self, parent, app, colors):
        super().__init__(parent, app, colors)

        # Process tree state
        self.pid_to_tree_item = {}
        self.process_tree_initial_load = True

        # Widget references
        self.process_tree = None
        self.process_search_entry = None
        self.process_filter_var = None
        self.process_filter_dropdown = None
        self.btn_toggle_process_monitor = None
        self.yara_match_badge = None
        self.sigma_match_badge = None
        self.http_alert_badge = None

        # HTTP panel state
        self.http_panel_visible = False
        self._process_paned = None
        self._http_panel = None
        self.http_tree = None
        self.http_stats_label = None
        self.http_pid_filter_label = None
        self.http_pid_lock_var = None
        self.http_alerts_only_var = None
        self.http_context_menu = None
        self._http_session_data = {}
        self._http_selected_pid = None
        self._http_refresh_job = None

        # Process context menu
        self.process_context_menu = None
        self.process_conn_menu = None

        # Quick Strings panel state
        self._strings_panel_visible = False
        self._strings_panel = None          # tk.Frame inside PanedWindow
        self._strings_analysis = None       # StringAnalysisPanel instance
        self._strings_cache = {}            # pid -> extraction_result
        self._strings_selected_pid = None
        self._strings_popout_window = None

        self._build()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build(self):
        """Build the Processes sub-tab UI."""
        frame = self.frame

        # Header with controls
        header = ctk.CTkFrame(frame, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=10)

        title = ctk.CTkLabel(header, text="Process Analysis",
                             font=Fonts.title_large, text_color="white")
        title.pack(side="left")

        # Monitor toggle
        self.btn_toggle_process_monitor = ctk.CTkButton(
            header, text="▶ Start Monitoring",
            command=self.toggle_process_monitoring,
            height=35, width=150,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"]
        )
        self.btn_toggle_process_monitor.pack(side="right", padx=5)

        # Scan All button
        btn_scan_all = ctk.CTkButton(
            header, text="🔍 Scan All",
            command=self.scan_all_processes,
            height=35, width=100,
            fg_color="#8B4513",
            hover_color="#A0522D"
        )
        btn_scan_all.pack(side="right", padx=5)

        # Refresh button
        btn_refresh = ctk.CTkButton(
            header, text="🔄 Refresh",
            command=self.refresh_process_list,
            height=35, width=100,
            fg_color=self.colors["navy"],
            hover_color=self.colors["dark_blue"]
        )
        btn_refresh.pack(side="right", padx=5)

        # Search bar
        search_frame = ctk.CTkFrame(frame, fg_color="transparent")
        search_frame.pack(fill="x", padx=20, pady=(0, 10))

        search_label = ctk.CTkLabel(search_frame, text="🔍 Search:",
                                    font=Fonts.body, text_color="white")
        search_label.pack(side="left", padx=(0, 10))

        self.process_search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="PID or Process Name...",
            height=35,
            width=220 if self.is_large_screen else 140,
            fg_color="gray20",
            border_color=self.colors["navy"],
            border_width=2
        )
        self.process_search_entry.pack(side="left", padx=5)
        self.process_search_entry.bind("<KeyRelease>", lambda e: self.filter_processes())

        # Clear search button
        btn_clear_search = ctk.CTkButton(
            search_frame, text="✕ Clear",
            command=self.clear_process_search,
            height=35, width=80,
            fg_color="gray30",
            hover_color="gray40"
        )
        btn_clear_search.pack(side="left", padx=5)

        # Filter dropdown
        filter_label = ctk.CTkLabel(search_frame, text="Filter:",
                                    font=Fonts.body, text_color="white")
        filter_label.pack(side="left", padx=(10, 5))

        self.process_filter_var = ctk.StringVar(value="All Processes")
        self.process_filter_dropdown = ctk.CTkComboBox(
            search_frame,
            values=["All Processes", "YARA Matches Only", "Sigma Matches Only", "Benign Only", "Not Scanned"],
            variable=self.process_filter_var,
            command=lambda choice: self.filter_processes(),
            height=35,
            width=170 if self.is_large_screen else 130,
            fg_color="gray20",
            border_color=self.colors["navy"],
            button_color=self.colors["navy"],
            button_hover_color=self.colors["dark_blue"]
        )
        self.process_filter_dropdown.pack(side="left", padx=3)

        # YARA match counter badge
        self.yara_match_badge = ctk.CTkButton(
            search_frame, text="YARA: 0",
            command=self._show_yara_matches_popup,
            font=("Segoe UI", 14, "bold"),
            text_color="#9ca3af",
            fg_color="#374151", hover_color="#374151",
            corner_radius=6, height=30, width=100
        )
        self.yara_match_badge.pack(side="left", padx=(8, 3))

        # Sigma match counter badge
        self.sigma_match_badge = ctk.CTkButton(
            search_frame, text="SIGMA: 0",
            command=self._show_sigma_matches_popup,
            font=("Segoe UI", 14, "bold"),
            text_color="#9ca3af",
            fg_color="#374151", hover_color="#374151",
            corner_radius=6, height=30, width=110
        )
        self.sigma_match_badge.pack(side="left", padx=3)

        # HTTP Traffic badge
        self.http_alert_badge = ctk.CTkButton(
            search_frame, text="HTTP ▾",
            command=self._toggle_http_panel,
            font=("Segoe UI", 14, "bold"),
            text_color="#9ca3af",
            fg_color="#374151", hover_color="#374151",
            corner_radius=6, height=30, width=90
        )
        self.http_alert_badge.pack(side="left", padx=3)

        # Quick Strings toggle badge
        self._strings_badge = ctk.CTkButton(
            search_frame, text="Strings \u25be",
            command=self._toggle_quick_strings_panel,
            font=("Segoe UI", 14, "bold"),
            text_color="#9ca3af",
            fg_color="#374151", hover_color="#374151",
            corner_radius=6, height=30, width=100
        )
        self._strings_badge.pack(side="left", padx=3)

        # Paned container for process tree + HTTP panel
        paned_container = ctk.CTkFrame(frame, fg_color="transparent")
        paned_container.pack(fill="both", expand=True, padx=20, pady=10)

        self._process_paned = tk.PanedWindow(
            paned_container, orient=tk.VERTICAL,
            bg=self.colors["navy"], sashwidth=6, sashrelief="flat",
            borderwidth=0
        )
        self._process_paned.pack(fill="both", expand=True)

        # Process tree area
        tree_frame = tk.Frame(self._process_paned, bg="#1a1a1a")
        self._process_paned.add(tree_frame, stretch="always")

        # Scrollbars
        vsb = tk.Scrollbar(tree_frame, orient="vertical", bg="#1a1a1a", troughcolor="#0d1520")
        hsb = tk.Scrollbar(tree_frame, orient="horizontal", bg="#1a1a1a", troughcolor="#0d1520")
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")

        # Style for Treeview
        style = ttk.Style()
        style.theme_use('default')

        _tree_font_size = 14 if self.is_large_screen else 11
        _tree_heading_size = 15 if self.is_large_screen else 12
        _tree_row_height = 32 if self.is_large_screen else 24

        style.configure("Process.Treeview",
                        background="#1a1a1a", foreground="white",
                        fieldbackground="#1a1a1a", borderwidth=0,
                        relief="flat", font=('Segoe UI', _tree_font_size),
                        rowheight=_tree_row_height)

        style.configure("Process.Treeview.Heading",
                        background="#0d1520", foreground="white",
                        borderwidth=1, relief="flat",
                        font=('Segoe UI', _tree_heading_size, 'bold'))

        style.map("Process.Treeview",
                  background=[('selected', '#dc2626')],
                  foreground=[('selected', 'white')])

        style.map("Process.Treeview.Heading",
                  background=[('active', '#1a2332')])

        # Treeview with hierarchy support
        columns = ("PID", "File Path", "Bytes", "Connections", "Detection Status")
        self.process_tree = ttk.Treeview(
            tree_frame, columns=columns, show="tree headings",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
            style="Process.Treeview"
        )
        self.process_tree.pack(side="left", fill="both", expand=True)
        vsb.config(command=self.process_tree.yview)
        hsb.config(command=self.process_tree.xview)

        # Configure columns
        self.process_tree.column("#0", width=250, minwidth=180)
        self.process_tree.column("PID", width=80, minwidth=60, anchor="center")
        self.process_tree.column("File Path", width=350, minwidth=200)
        self.process_tree.column("Bytes", width=120, minwidth=80, anchor="e")
        self.process_tree.column("Connections", width=200, minwidth=120, anchor="center")
        self.process_tree.column("Detection Status", width=300, minwidth=180, anchor="center")

        # Headers
        self.process_tree.heading("#0", text="Process Tree")
        self.process_tree.heading("PID", text="PID")
        self.process_tree.heading("File Path", text="File Path")
        self.process_tree.heading("Bytes", text="Bytes")
        self.process_tree.heading("Connections", text="Network Connections")
        self.process_tree.heading("Detection Status", text="YARA / Sigma")

        # Right-click context menu
        self.process_context_menu = tk.Menu(
            self.process_tree, tearoff=0,
            bg="#1a1a1a", fg="white",
            activebackground="#dc2626", activeforeground="white",
            borderwidth=0, relief="flat"
        )
        self.process_context_menu.add_command(
            label="🔍 Scan with YARA", command=self.scan_selected_process)
        self.process_context_menu.add_command(
            label="📋 View Details & Strings", command=self.view_process_details_and_strings)
        self.process_context_menu.add_command(
            label="📂 Open Folder Location", command=self.open_folder_location)
        self.process_context_menu.add_separator(background="#444444")

        # Network connection IOC submenu
        self.process_conn_menu = tk.Menu(
            self.process_context_menu, tearoff=0,
            bg="#1a1a1a", fg="white",
            activebackground="#dc2626", activeforeground="white",
            borderwidth=0, relief="flat"
        )
        self.process_conn_menu.add_command(
            label="Add Remote IP to Case",
            command=lambda: self.add_process_conn_ioc_to_case("remote_ip"))
        self.process_conn_menu.add_command(
            label="Add Remote Hostname to Case",
            command=lambda: self.add_process_conn_ioc_to_case("hostname"))
        self.process_conn_menu.add_command(
            label="Add All Connection IPs to Case",
            command=lambda: self.add_process_conn_ioc_to_case("all_ips"))
        self.process_context_menu.add_cascade(
            label="🌐 Add Connection to Case", menu=self.process_conn_menu)
        self.process_context_menu.add_separator(background="#444444")
        self.process_context_menu.add_command(
            label="❌ Kill Process", command=self.kill_selected_process)

        self.process_tree.bind("<Button-3>", self.show_process_context_menu)
        self.process_tree.bind("<Double-1>", lambda e: self.view_process_details_and_strings())

        # Configure tag colors
        self.process_tree.tag_configure('threat', background='#5c1c1c', foreground='white')
        self.process_tree.tag_configure('new', background='#8B7500', foreground='white')
        self.process_tree.tag_configure('benign', background='#1a4d2e', foreground='white')
        self.process_tree.tag_configure('system', foreground='#888888')
        self.process_tree.tag_configure('suspended', background='#3a3a3a', foreground='#808080')
        self.process_tree.tag_configure('sigma_match', background='#4c1d95', foreground='#c084fc')

        # Build HTTP panel
        self._build_http_panel()

        # Build Quick Strings panel (collapsible, below the tree)
        self._build_quick_strings_panel()

        # Auto-filter when process tree selection changes
        self.process_tree.bind("<<TreeviewSelect>>", self._on_process_select_for_http)
        self.process_tree.bind("<<TreeviewSelect>>", self._on_process_select_for_strings, add="+")

        # Initial load
        self.refresh_process_list()

    def _build_http_panel(self):
        """Build the collapsible HTTP traffic panel."""
        self._http_panel = tk.Frame(self._process_paned, bg=self.colors["navy"])

        # HTTP header bar
        http_header = tk.Frame(self._http_panel, bg=self.colors["dark_blue"], height=36)
        http_header.pack(fill="x")
        http_header.pack_propagate(False)

        tk.Label(http_header, text="HTTP Traffic",
                 bg=self.colors["dark_blue"], fg="#a78bfa",
                 font=("Segoe UI", 12, "bold")).pack(side="left", padx=10)

        self.http_stats_label = tk.Label(
            http_header, text="Sessions: 0  |  Alerts: 0",
            bg=self.colors["dark_blue"], fg="#9ca3af",
            font=("Segoe UI", 10))
        self.http_stats_label.pack(side="left", padx=15)

        # PID filter indicator
        self.http_pid_filter_label = tk.Label(
            http_header, text="All Processes",
            bg=self.colors["dark_blue"], fg="#22d3ee",
            font=("Segoe UI", 10))
        self.http_pid_filter_label.pack(side="left", padx=5)

        # Filter to selected PID checkbox
        self.http_pid_lock_var = tk.BooleanVar(value=False)
        self.http_pid_lock_check = tk.Checkbutton(
            http_header, text="Filter to PID",
            variable=self.http_pid_lock_var,
            command=self._refresh_http_tree,
            bg=self.colors["dark_blue"], fg="#22d3ee",
            selectcolor=self.colors["navy"],
            activebackground=self.colors["dark_blue"], activeforeground="#22d3ee",
            font=("Segoe UI", 10))
        self.http_pid_lock_check.pack(side="right", padx=5)

        # Alerts only checkbox
        self.http_alerts_only_var = tk.BooleanVar(value=False)
        self.http_alerts_check = tk.Checkbutton(
            http_header, text="Alerts Only",
            variable=self.http_alerts_only_var,
            command=self._refresh_http_tree,
            bg=self.colors["dark_blue"], fg="#fbbf24",
            selectcolor=self.colors["navy"],
            activebackground=self.colors["dark_blue"], activeforeground="#fbbf24",
            font=("Segoe UI", 10))
        self.http_alerts_check.pack(side="right", padx=10)

        # Clear button
        tk.Button(http_header, text="Clear",
                  bg=self.colors["dark_blue"], fg="white",
                  activebackground=self.colors["red_dark"], activeforeground="white",
                  relief="flat", bd=0, padx=8, font=("Segoe UI", 9),
                  command=self._clear_http_sessions).pack(side="right", padx=5)

        # HTTP Treeview
        http_tree_frame = tk.Frame(self._http_panel, bg=self.colors["navy"])
        http_tree_frame.pack(fill="both", expand=True)

        http_vsb = tk.Scrollbar(http_tree_frame, orient="vertical")
        http_vsb.pack(side="right", fill="y")

        http_columns = ("#", "Time", "PID", "Process", "Protocol",
                        "Host", "Remote", "Status", "Alert")
        self.http_tree = ttk.Treeview(
            http_tree_frame, columns=http_columns, show="headings",
            yscrollcommand=http_vsb.set, style="Process.Treeview"
        )
        self.http_tree.pack(side="left", fill="both", expand=True)
        http_vsb.config(command=self.http_tree.yview)

        col_widths = {"#": 50, "Time": 100, "PID": 60, "Process": 130,
                      "Protocol": 70, "Host": 250, "Remote": 150,
                      "Status": 100, "Alert": 80}
        for col in http_columns:
            self.http_tree.heading(col, text=col)
            self.http_tree.column(col, width=col_widths.get(col, 100), minwidth=40)

        # Alert-level tag colours
        self.http_tree.tag_configure("high", background="#7f1d1d", foreground="#fca5a5")
        self.http_tree.tag_configure("medium", background="#78350f", foreground="#fbbf24")
        self.http_tree.tag_configure("low", background=self.colors["dark_blue"], foreground="#c4b5fd")

        # HTTP right-click context menu
        self.http_context_menu = tk.Menu(
            self.http_tree, tearoff=0,
            bg=self.colors["navy"], fg="white",
            activebackground=self.colors["red"], activeforeground="white",
            borderwidth=0, relief="flat"
        )
        self.http_context_menu.add_command(
            label="📋 Copy Host", command=lambda: self._copy_http_cell("Host"))
        self.http_context_menu.add_command(
            label="📋 Copy Remote Address", command=lambda: self._copy_http_cell("Remote"))
        self.http_context_menu.add_command(
            label="📋 Copy Row", command=self._copy_http_row)
        self.http_context_menu.add_separator(background="#444444")
        self.http_context_menu.add_command(
            label="➕ Add Host to IOCs", command=lambda: self._add_http_ioc("host"))
        self.http_context_menu.add_command(
            label="➕ Add IP to IOCs", command=lambda: self._add_http_ioc("ip"))
        self.http_context_menu.add_separator(background="#444444")
        self.http_context_menu.add_command(
            label="🔍 Focus Process in Tree", command=self._focus_http_process)

        self.http_tree.bind("<Button-3>", self._show_http_context_menu)
        self.http_tree.bind("<Double-1>", lambda e: self._show_http_session_detail())


    # ------------------------------------------------------------------
    # Process monitoring toggle / auto-refresh
    # ------------------------------------------------------------------

    def toggle_process_monitoring(self):
        """Toggle process monitoring on/off."""
        if not self.app.process_monitor_active:
            self.app.process_monitor.start_monitoring()
            self.app.process_monitor_active = True
            self.btn_toggle_process_monitor.configure(text="⏸ Stop Monitoring")
            self.start_auto_refresh()
            messagebox.showinfo("Monitoring Active",
                                "Process monitoring started. New processes will be automatically scanned with YARA.")
        else:
            self.app.process_monitor.stop_monitoring()
            self.app.process_monitor_active = False
            self.btn_toggle_process_monitor.configure(text="▶ Start Monitoring")
            self.stop_auto_refresh()

    def start_auto_refresh(self):
        """Start automatic process tree refresh."""
        if not self.app.auto_refresh_enabled:
            return
        if self.app.auto_refresh_job:
            self.root.after_cancel(self.app.auto_refresh_job)

        def auto_refresh_callback():
            if self.app.process_monitor_active and self.app.auto_refresh_enabled:
                self.refresh_process_list()
                self.app.auto_refresh_job = self.root.after(
                    self.app.auto_refresh_interval, auto_refresh_callback)

        self.app.auto_refresh_job = self.root.after(
            self.app.auto_refresh_interval, auto_refresh_callback)

    def stop_auto_refresh(self):
        """Stop automatic process tree refresh."""
        if self.app.auto_refresh_job:
            self.root.after_cancel(self.app.auto_refresh_job)
            self.app.auto_refresh_job = None

    # ------------------------------------------------------------------
    # Process tree refresh (incremental updates)
    # ------------------------------------------------------------------

    def refresh_process_list(self):
        """Refresh the process tree with parent-child hierarchy using incremental updates."""
        search_text = self.process_search_entry.get().strip() if self.process_search_entry else ""
        filter_choice = self.process_filter_var.get() if self.process_filter_var else "All Processes"

        if search_text or filter_choice != "All Processes":
            self.filter_processes()
            return

        processes = self.app.process_monitor.get_all_processes()
        process_map = {proc['pid']: proc for proc in processes}
        current_pids = set(process_map.keys())
        existing_pids = set(self.pid_to_tree_item.keys())

        pids_to_add = current_pids - existing_pids
        dead_pids = existing_pids - current_pids
        potentially_updated_pids = current_pids & existing_pids

        if self.process_tree_initial_load:
            new_pids = set()
        else:
            new_pids = pids_to_add

        # Save expanded and selected state
        expanded_pids = set()
        for pid in existing_pids:
            if pid in self.pid_to_tree_item:
                item_id = self.pid_to_tree_item[pid]
                try:
                    if self.process_tree.exists(item_id):
                        if self.process_tree.item(item_id, 'open'):
                            expanded_pids.add(pid)
                except:
                    pass

        selected_pid = self._get_selected_pid()

        # Remove dead processes
        for pid in dead_pids:
            if pid in self.pid_to_tree_item:
                try:
                    self.process_tree.delete(self.pid_to_tree_item[pid])
                except:
                    pass
                del self.pid_to_tree_item[pid]

        # Update existing processes
        for pid in potentially_updated_pids:
            if pid not in self.pid_to_tree_item:
                continue

            proc = process_map[pid]
            item_id = self.pid_to_tree_item[pid]

            try:
                if not self.process_tree.exists(item_id):
                    new_pids.add(pid)
                    del self.pid_to_tree_item[pid]
                    continue

                current_values = self.process_tree.item(item_id, 'values')

                is_suspended = False
                try:
                    import psutil
                    process_status = psutil.Process(pid).status()
                    is_suspended = process_status == psutil.STATUS_STOPPED
                except:
                    pass

                yara_status = "No"
                tags = ()
                if is_suspended:
                    yara_status = "⏸️ SUSPENDED"
                    tags = ('suspended',)
                elif proc.get('threat_detected'):
                    yara_rule = proc.get('yara_rule', 'Unknown')
                    if yara_rule and yara_rule != 'Unknown':
                        scan_results = proc.get('scan_results', {})
                        all_rules = scan_results.get('all_rules', [yara_rule])
                        if len(all_rules) > 1:
                            yara_status = f"⚠️ {yara_rule} +{len(all_rules) - 1}"
                        else:
                            yara_status = f"⚠️ {yara_rule}"
                    else:
                        matches = proc.get('yara_matches', 0)
                        yara_status = f"⚠️ {matches} matches" if matches else "⚠️ YES"
                    tags = ('threat',)
                elif proc.get('whitelisted', False):
                    yara_status = "✅ BENIGN"
                    tags = ('benign',)
                elif pid in new_pids:
                    tags = ('new',)
                elif proc['name'].lower() in ['system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe']:
                    tags = ('system',)

                sigma_titles = self.app.evaluate_process_sigma(proc)
                if sigma_titles:
                    sigma_label = f"🔷 SIGMA ({len(sigma_titles)})" if len(sigma_titles) > 1 else f"🔷 SIGMA"
                    if yara_status != "No":
                        yara_status = f"{yara_status} | {sigma_label}"
                    else:
                        yara_status = sigma_label
                    if not tags or tags == ('new',) or tags == ('system',):
                        tags = ('sigma_match',)

                conn_summary = self._get_process_connections_summary(pid)
                private_bytes = self._format_private_bytes(proc.get('private_bytes', 0))
                new_values = (pid, proc.get('exe', 'N/A'), private_bytes, conn_summary, yara_status)

                if len(current_values) != len(new_values) or tuple(str(v) for v in current_values) != tuple(str(v) for v in new_values):
                    self.process_tree.item(item_id, values=new_values, tags=tags)
            except Exception:
                if pid in self.pid_to_tree_item:
                    del self.pid_to_tree_item[pid]
                pids_to_add.add(pid)
                if not self.process_tree_initial_load:
                    new_pids.add(pid)

        # Add new processes
        if pids_to_add:
            children_map = {}
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

                is_suspended = False
                try:
                    import psutil
                    process_status = psutil.Process(pid).status()
                    is_suspended = process_status == psutil.STATUS_STOPPED
                except:
                    pass

                yara_status = "No"
                tags = ()
                if is_suspended:
                    yara_status = "⏸️ SUSPENDED"
                    tags = ('suspended',)
                elif proc.get('threat_detected'):
                    yara_rule = proc.get('yara_rule', 'Unknown')
                    if yara_rule and yara_rule != 'Unknown':
                        scan_results = proc.get('scan_results', {})
                        all_rules = scan_results.get('all_rules', [yara_rule])
                        if len(all_rules) > 1:
                            yara_status = f"⚠️ {yara_rule} +{len(all_rules) - 1}"
                        else:
                            yara_status = f"⚠️ {yara_rule}"
                    else:
                        matches = proc.get('yara_matches', 0)
                        yara_status = f"⚠️ {matches} matches" if matches else "⚠️ YES"
                    tags = ('threat',)
                elif proc.get('whitelisted', False):
                    yara_status = "✅ BENIGN"
                    tags = ('benign',)
                elif pid in new_pids:
                    tags = ('new',)
                elif name.lower() in ['system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe']:
                    tags = ('system',)

                sigma_titles = self.app.evaluate_process_sigma(proc)
                if sigma_titles:
                    sigma_label = f"🔷 SIGMA ({len(sigma_titles)})" if len(sigma_titles) > 1 else f"🔷 SIGMA"
                    if yara_status != "No":
                        yara_status = f"{yara_status} | {sigma_label}"
                    else:
                        yara_status = sigma_label
                    if not tags or tags == ('new',) or tags == ('system',):
                        tags = ('sigma_match',)

                conn_summary = self._get_process_connections_summary(pid)
                private_bytes = self._format_private_bytes(proc.get('private_bytes', 0))

                item_id = self.process_tree.insert(
                    parent_id, "end", text=f"  {name}",
                    values=(pid, exe, private_bytes, conn_summary, yara_status),
                    tags=tags, open=pid in expanded_pids
                )
                self.pid_to_tree_item[pid] = item_id

                if pid in children_map:
                    for child in children_map[pid]:
                        add_process_tree(child, item_id)

            for proc in root_processes:
                if proc['pid'] in pids_to_add or proc['pid'] not in self.pid_to_tree_item:
                    add_process_tree(proc)

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

        self._restore_selected_pid(selected_pid)
        self._update_sigma_badge_from_tree()

        if self.process_tree_initial_load:
            self.process_tree_initial_load = False

    # ------------------------------------------------------------------
    # Filter / search
    # ------------------------------------------------------------------

    def filter_processes(self):
        """Filter processes by PID or Name, showing matching processes and all their children."""
        search_text = self.process_search_entry.get().strip().lower()
        filter_choice = self.process_filter_var.get() if self.process_filter_var else "All Processes"

        selected_pid = self._get_selected_pid()

        if not search_text and filter_choice == "All Processes":
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)
            self.pid_to_tree_item.clear()

            was_initial_load = self.process_tree_initial_load
            self.process_tree_initial_load = True
            self.refresh_process_list()
            self.process_tree_initial_load = was_initial_load

            self._restore_selected_pid(selected_pid)
            self._update_sigma_badge_from_tree()
            return

        processes = self.app.process_monitor.get_all_processes()
        process_map = {proc['pid']: proc for proc in processes}

        children_map = {}
        for proc in processes:
            ppid = proc.get('ppid')
            if ppid and ppid in process_map and ppid != proc['pid']:
                if ppid not in children_map:
                    children_map[ppid] = []
                children_map[ppid].append(proc)

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
            elif filter_choice == "Sigma Matches Only":
                filter_match = len(self.app.evaluate_process_sigma(proc)) > 0
            elif filter_choice == "Benign Only":
                filter_match = proc.get('whitelisted', False)
            elif filter_choice == "Not Scanned":
                filter_match = not proc.get('threat_detected', False) and not proc.get('whitelisted', False)

            if search_match and filter_match:
                matching_pids.add(proc['pid'])

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

        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        self.pid_to_tree_item.clear()

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
                        yara_status = f"⚠️ {yara_rule} +{len(all_rules) - 1}"
                    else:
                        yara_status = f"⚠️ {yara_rule}"
                else:
                    matches = proc.get('yara_matches', 0)
                    yara_status = f"⚠️ {matches} matches" if matches else "⚠️ YES"
                tags = ('threat',)
            elif name.lower() in ['system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe']:
                tags = ('system',)

            sigma_titles = self.app.evaluate_process_sigma(proc)
            if sigma_titles:
                sigma_label = f"🔷 SIGMA ({len(sigma_titles)})" if len(sigma_titles) > 1 else f"🔷 SIGMA"
                if yara_status != "No":
                    yara_status = f"{yara_status} | {sigma_label}"
                else:
                    yara_status = sigma_label
                if not tags or tags == ('system',):
                    tags = ('sigma_match',)

            conn_summary = self._get_process_connections_summary(pid)
            private_bytes = self._format_private_bytes(proc.get('private_bytes', 0))

            item_id = self.process_tree.insert(
                parent_id, "end", text=f"  {name}",
                values=(pid, exe, private_bytes, conn_summary, yara_status),
                tags=tags, open=True
            )
            self.pid_to_tree_item[pid] = item_id

            if pid in children_map:
                for child in children_map[pid]:
                    if child['pid'] in pids_to_show:
                        add_process_to_tree(child, item_id)

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

        self._restore_selected_pid(selected_pid)
        self._update_sigma_badge_from_tree()

    def clear_process_search(self):
        """Clear the process search and show all processes."""
        self.process_search_entry.delete(0, tk.END)
        self.refresh_process_list()

    # ------------------------------------------------------------------
    # Tree helpers
    # ------------------------------------------------------------------

    def _get_selected_pid(self):
        """Get the PID of the currently selected process in the tree."""
        selection = self.process_tree.selection()
        if selection:
            try:
                values = self.process_tree.item(selection[0], 'values')
                if values and len(values) > 0:
                    return int(values[0])
            except:
                pass
        return None

    def _restore_selected_pid(self, pid):
        """Restore selection to a process by PID after tree rebuild."""
        if pid and pid in self.pid_to_tree_item:
            try:
                item_id = self.pid_to_tree_item[pid]
                if self.process_tree.exists(item_id):
                    self.process_tree.selection_set(item_id)
                    self.process_tree.see(item_id)
            except:
                pass

    def focus_process_by_pid(self, target_pid):
        """Focus on a specific process in the tree by PID."""
        try:
            if target_pid not in self.pid_to_tree_item:
                self.refresh_process_list()
                self.root.after(1000, lambda: self.focus_process_by_pid(target_pid))
                return

            item_id = self.pid_to_tree_item[target_pid]
            parent = self.process_tree.parent(item_id)
            while parent:
                self.process_tree.item(parent, open=True)
                parent = self.process_tree.parent(parent)

            self.process_tree.selection_set(item_id)
            self.process_tree.see(item_id)
            self.process_tree.focus(item_id)
        except Exception as e:
            print(f"Error focusing on PID {target_pid}: {e}")

    def _format_private_bytes(self, num_bytes):
        """Format bytes into human-readable size."""
        if not num_bytes or num_bytes == 0:
            return "0 B"
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        unit_index = 0
        size = float(num_bytes)
        while size >= 1024.0 and unit_index < len(units) - 1:
            size /= 1024.0
            unit_index += 1
        if unit_index == 0:
            return f"{int(size)} B"
        return f"{size:,.1f} {units[unit_index]}"

    def _get_process_connections_summary(self, pid):
        """Get a summary string of network connections for a process."""
        try:
            connections = self._get_process_connections(pid)
            if not connections:
                return "None"
            count = len(connections)
            remote_ips = set()
            for conn in connections:
                rip = conn.get('remote_ip', '')
                if rip and rip not in ('', '0.0.0.0', '::', '127.0.0.1', '::1'):
                    remote_ips.add(rip)
            suspicious_count = sum(1 for c in connections if c.get('suspicious'))
            if suspicious_count:
                return f"⚠️ {count} ({suspicious_count} suspicious)"
            elif remote_ips:
                if len(remote_ips) == 1:
                    return f"{count} → {next(iter(remote_ips))}"
                return f"{count} → {len(remote_ips)} IPs"
            else:
                return f"{count} (local)"
        except Exception:
            return "None"

    def _get_process_connections(self, pid):
        """Get live network connections for a process directly via psutil."""
        try:
            import psutil
            proc = psutil.Process(pid)
            raw_conns = proc.net_connections(kind='inet')
            connections = []
            for conn in raw_conns:
                conn_info = {
                    'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6',
                    'type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP',
                    'local_ip': conn.laddr.ip if conn.laddr else None,
                    'local_port': conn.laddr.port if conn.laddr else None,
                    'remote_ip': conn.raddr.ip if conn.raddr else None,
                    'remote_port': conn.raddr.port if conn.raddr else None,
                    'status': conn.status,
                    'pid': pid,
                }
                remote_port = conn_info.get('remote_port')
                if remote_port and remote_port in (4444, 4445, 5555, 6666, 7777, 8888, 31337, 12345):
                    conn_info['suspicious'] = True
                remote_ip = conn_info.get('remote_ip', '')
                if remote_ip:
                    hostname = self.app.resolve_hostname(remote_ip)
                    if hostname and hostname != '-':
                        conn_info['remote_hostname'] = hostname
                connections.append(conn_info)
            return connections
        except Exception:
            return []

    def get_child_pids_recursive(self, parent_pid):
        """Get all child PIDs recursively for a given parent PID."""
        child_pids = set()
        processes = self.app.process_monitor.get_all_processes()
        children_map = {}
        for proc in processes:
            ppid = proc.get('ppid')
            if ppid:
                if ppid not in children_map:
                    children_map[ppid] = []
                children_map[ppid].append(proc['pid'])

        def get_children(pid):
            if pid in children_map:
                for child_pid in children_map[pid]:
                    child_pids.add(child_pid)
                    get_children(child_pid)

        get_children(parent_pid)
        return child_pids

    # ------------------------------------------------------------------
    # Badge updates
    # ------------------------------------------------------------------

    def _update_sigma_badge_from_tree(self):
        """Count Sigma matches in the process tree and update the badge."""
        if not self.app.sigma_evaluator:
            return
        sigma_count = sum(1 for titles in self.app._process_sigma_cache.values() if titles)
        if sigma_count != self.app.total_sigma_matches:
            self.app.total_sigma_matches = sigma_count
            self.update_sigma_match_badge()

    def update_yara_match_badge(self):
        """Update the YARA match counter badge with current count and color coding."""
        count = self.app.total_yara_matches
        self.yara_match_badge.configure(text=f"YARA: {count}")
        if count == 0:
            self.yara_match_badge.configure(
                text_color="#9ca3af", fg_color="#374151", hover_color="#374151")
        elif count <= 10:
            self.yara_match_badge.configure(
                text_color="#fbbf24", fg_color="#78350f", hover_color="#92400e")
        elif count <= 25:
            self.yara_match_badge.configure(
                text_color="#fb923c", fg_color="#7c2d12", hover_color="#9a3412")
        else:
            self.yara_match_badge.configure(
                text_color="#f87171", fg_color="#7f1d1d", hover_color="#991b1b")

    def update_sigma_match_badge(self):
        """Update the Sigma match counter badge with current count and color coding."""
        count = self.app.total_sigma_matches
        self.sigma_match_badge.configure(text=f"SIGMA: {count}")
        if count == 0:
            self.sigma_match_badge.configure(
                text_color="#9ca3af", fg_color="#374151", hover_color="#374151")
        elif count <= 10:
            self.sigma_match_badge.configure(
                text_color="#a78bfa", fg_color="#4c1d95", hover_color="#5b21b6")
        elif count <= 25:
            self.sigma_match_badge.configure(
                text_color="#c084fc", fg_color="#581c87", hover_color="#6b21a8")
        else:
            self.sigma_match_badge.configure(
                text_color="#e879f9", fg_color="#701a75", hover_color="#86198f")

    # ------------------------------------------------------------------
    # YARA / Sigma match popups
    # ------------------------------------------------------------------

    def _show_yara_matches_popup(self):
        """Show a popup listing all processes with YARA matches."""
        processes = self.app.process_monitor.get_all_processes()
        matched = []
        for proc in processes:
            if proc.get('threat_detected') and proc.get('yara_rule') and proc['yara_rule'] != 'No_YARA_Hit':
                scan_results = proc.get('scan_results', {})
                all_rules = scan_results.get('all_rules', [proc.get('yara_rule', 'Unknown')])
                matched.append({
                    'pid': proc['pid'], 'name': proc['name'],
                    'exe': proc.get('exe', 'N/A'), 'rules': all_rules
                })

        popup = ctk.CTkToplevel(self.root)
        popup.title("YARA Matches")
        popup.geometry("650x420")
        popup.attributes('-topmost', True)

        main = ctk.CTkFrame(popup, fg_color=self.colors["navy"])
        main.pack(fill="both", expand=True, padx=2, pady=2)

        header = ctk.CTkLabel(main, text=f"YARA Matches ({len(matched)} processes)",
                              font=Fonts.title_large, text_color="#fbbf24")
        header.pack(padx=15, pady=(15, 10))

        if not matched:
            ctk.CTkLabel(main, text="No YARA matches found.",
                         font=Fonts.body, text_color="gray60").pack(pady=20)
        else:
            text_frame = ctk.CTkFrame(main, fg_color=self.colors["dark_blue"], corner_radius=8)
            text_frame.pack(fill="both", expand=True, padx=15, pady=(0, 10))

            text_box = ctk.CTkTextbox(text_frame, fg_color=self.colors["dark_blue"],
                                      text_color="white", font=Fonts.body, wrap="word")
            text_box.pack(fill="both", expand=True, padx=5, pady=5)

            for m in sorted(matched, key=lambda x: len(x['rules']), reverse=True):
                text_box.insert("end", f"PID {m['pid']}  {m['name']}\n", "proc")
                text_box.insert("end", f"  {m['exe']}\n", "path")
                for rule in m['rules']:
                    text_box.insert("end", f"    ⚠️ {rule}\n", "rule")
                text_box.insert("end", "\n")

            text_box.tag_config("proc", foreground="#fbbf24")
            text_box.tag_config("path", foreground="#9ca3af")
            text_box.tag_config("rule", foreground="#f87171")
            text_box.configure(state="disabled")

        ctk.CTkButton(main, text="Close", command=popup.destroy,
                      fg_color=self.colors["red"], hover_color=self.colors["red_dark"],
                      height=32, width=100).pack(pady=(0, 15))

    def _show_sigma_matches_popup(self):
        """Show a popup listing all processes with Sigma matches."""
        processes = self.app.process_monitor.get_all_processes()
        matched = []
        for proc in processes:
            sigma_titles = self.app.evaluate_process_sigma(proc)
            if sigma_titles:
                matched.append({
                    'pid': proc['pid'], 'name': proc['name'],
                    'exe': proc.get('exe', 'N/A'), 'rules': sigma_titles
                })

        popup = ctk.CTkToplevel(self.root)
        popup.title("Sigma Matches")
        popup.geometry("650x420")
        popup.attributes('-topmost', True)

        main = ctk.CTkFrame(popup, fg_color=self.colors["navy"])
        main.pack(fill="both", expand=True, padx=2, pady=2)

        header = ctk.CTkLabel(main, text=f"Sigma Matches ({len(matched)} processes)",
                              font=Fonts.title_large, text_color="#a78bfa")
        header.pack(padx=15, pady=(15, 10))

        if not matched:
            ctk.CTkLabel(main, text="No Sigma matches found.",
                         font=Fonts.body, text_color="gray60").pack(pady=20)
        else:
            text_frame = ctk.CTkFrame(main, fg_color=self.colors["dark_blue"], corner_radius=8)
            text_frame.pack(fill="both", expand=True, padx=15, pady=(0, 10))

            text_box = ctk.CTkTextbox(text_frame, fg_color=self.colors["dark_blue"],
                                      text_color="white", font=Fonts.body, wrap="word")
            text_box.pack(fill="both", expand=True, padx=5, pady=5)

            for m in sorted(matched, key=lambda x: len(x['rules']), reverse=True):
                text_box.insert("end", f"PID {m['pid']}  {m['name']}\n", "proc")
                text_box.insert("end", f"  {m['exe']}\n", "path")
                for rule in m['rules']:
                    text_box.insert("end", f"    🔷 {rule}\n", "rule")
                text_box.insert("end", "\n")

            text_box.tag_config("proc", foreground="#a78bfa")
            text_box.tag_config("path", foreground="#9ca3af")
            text_box.tag_config("rule", foreground="#c084fc")
            text_box.configure(state="disabled")

        ctk.CTkButton(main, text="Close", command=popup.destroy,
                      fg_color=self.colors["red"], hover_color=self.colors["red_dark"],
                      height=32, width=100).pack(pady=(0, 15))

    # ------------------------------------------------------------------
    # HTTP Traffic Panel methods
    # ------------------------------------------------------------------

    def _toggle_http_panel(self):
        """Show or hide the HTTP traffic panel."""
        if self.http_panel_visible:
            self._process_paned.forget(self._http_panel)
            self.http_panel_visible = False
            self.http_alert_badge.configure(
                text="HTTP ▾" if not self.app.http_monitor_active else
                self.http_alert_badge.cget("text").replace("▴", "▾"))
            if self.app.http_monitor_active:
                self.app.http_monitor.stop_monitoring()
                self.app.http_monitor_active = False
                if self._http_refresh_job:
                    self.root.after_cancel(self._http_refresh_job)
        else:
            self._process_paned.add(self._http_panel, stretch="always")
            self._process_paned.paneconfigure(self._http_panel, height=250)
            self.http_panel_visible = True
            self.http_alert_badge.configure(
                text=self.http_alert_badge.cget("text").replace("▾", "▴"))
            if not self.app.http_monitor_active:
                self.app.http_monitor.start_monitoring()
                self.app.http_monitor_active = True
                self._http_auto_refresh()

    def _http_auto_refresh(self):
        """Periodically refresh the HTTP tree while monitoring is active."""
        if not self.app.http_monitor_active or not self.http_panel_visible:
            return
        self._refresh_http_tree()
        self._http_refresh_job = self.root.after(1500, self._http_auto_refresh)

    def _refresh_http_tree(self):
        """Rebuild the HTTP tree from current sessions."""
        if not self.http_tree:
            return

        self.http_tree.delete(*self.http_tree.get_children())
        self._http_session_data.clear()

        pid_filter = None
        if self.http_pid_lock_var.get() and self._http_selected_pid:
            pid_filter = self._http_selected_pid
        alert_only = self.http_alerts_only_var.get()

        sessions = self.app.http_monitor.get_sessions(
            pid_filter=pid_filter, alert_only=alert_only)

        alert_count = 0
        for sess in sessions:
            tag = (sess.alert,) if sess.alert else ()
            if sess.alert:
                alert_count += 1
            alert_text = sess.alert.upper() if sess.alert else ""

            iid = self.http_tree.insert("", "end", values=(
                sess.id, sess.timestamp, sess.pid,
                sess.process_name[:20], sess.protocol,
                sess.host or sess.remote_ip,
                f"{sess.remote_ip}:{sess.remote_port}",
                sess.status, alert_text,
            ), tags=tag)
            self._http_session_data[iid] = sess

        stats = self.app.http_monitor.stats
        self.http_stats_label.configure(
            text=f"Sessions: {stats['total_sessions']}  |  "
                 f"Active: {stats['active_sessions']}  |  "
                 f"Alerts: {stats['alerts']}")

        if pid_filter:
            self.http_pid_filter_label.configure(text=f"PID {pid_filter}", fg="#22d3ee")
        else:
            self.http_pid_filter_label.configure(text="All Processes", fg="#9ca3af")

        arrow = "▴" if self.http_panel_visible else "▾"
        total_alerts = stats.get("alerts", 0)
        if total_alerts == 0:
            self.http_alert_badge.configure(
                text=f"HTTP {arrow}", text_color="#9ca3af",
                fg_color="#374151", hover_color="#374151")
        elif total_alerts <= 5:
            self.http_alert_badge.configure(
                text=f"HTTP: {total_alerts} {arrow}", text_color="#fbbf24",
                fg_color="#78350f", hover_color="#92400e")
        else:
            self.http_alert_badge.configure(
                text=f"HTTP: {total_alerts} {arrow}", text_color="#f87171",
                fg_color="#7f1d1d", hover_color="#991b1b")

    def _on_process_select_for_http(self, event=None):
        """Track the selected PID for optional HTTP filtering."""
        sel = self.process_tree.selection()
        if sel:
            try:
                values = self.process_tree.item(sel[0], "values")
                self._http_selected_pid = int(values[0])
            except (ValueError, IndexError):
                self._http_selected_pid = None
        else:
            self._http_selected_pid = None
        if self.http_panel_visible and self.http_pid_lock_var.get():
            self._refresh_http_tree()

    def _clear_http_sessions(self):
        """Clear all HTTP sessions."""
        self.app.http_monitor.clear()
        self._http_selected_pid = None
        self._refresh_http_tree()

    def _show_http_context_menu(self, event):
        item = self.http_tree.identify_row(event.y)
        if item:
            self.http_tree.selection_set(item)
            self.http_context_menu.tk_popup(event.x_root, event.y_root)

    def _copy_http_cell(self, col_name):
        sel = self.http_tree.selection()
        if not sel:
            return
        sess = self._http_session_data.get(sel[0])
        if not sess:
            return
        val = ""
        if col_name == "Host":
            val = sess.host or sess.remote_ip
        elif col_name == "Remote":
            val = f"{sess.remote_ip}:{sess.remote_port}"
        self.root.clipboard_clear()
        self.root.clipboard_append(val)

    def _copy_http_row(self):
        sel = self.http_tree.selection()
        if not sel:
            return
        values = self.http_tree.item(sel[0], "values")
        self.root.clipboard_clear()
        self.root.clipboard_append(" | ".join(str(v) for v in values))

    def _add_http_ioc(self, field_type):
        if not self.app.current_case:
            messagebox.showwarning("No Active Case", "No active case to add IOC to.")
            return
        sel = self.http_tree.selection()
        if not sel:
            return
        sess = self._http_session_data.get(sel[0])
        if not sess:
            return
        if field_type == "host" and sess.host:
            self.app.case_manager.add_ioc("domains", sess.host)
            self._refresh_iocs_display()
            messagebox.showinfo("Success", f"Added domain '{sess.host}' to case IOCs!")
        elif field_type == "ip":
            self.app.case_manager.add_ioc("ips", sess.remote_ip)
            self._refresh_iocs_display()
            messagebox.showinfo("Success", f"Added IP '{sess.remote_ip}' to case IOCs!")

    def _focus_http_process(self):
        """Select the process in the tree that matches the selected HTTP session."""
        sel = self.http_tree.selection()
        if not sel:
            return
        sess = self._http_session_data.get(sel[0])
        if not sess:
            return
        self.focus_process_by_pid(sess.pid)

    def _show_http_session_detail(self):
        """Show full detail popup for a double-clicked HTTP session."""
        sel = self.http_tree.selection()
        if not sel:
            return
        sess = self._http_session_data.get(sel[0])
        if not sess:
            return

        detail = ctk.CTkToplevel(self.root)
        detail.title(f"HTTP Session #{sess.id} — {sess.host or sess.remote_ip}")
        detail.geometry("640x450")
        detail.configure(fg_color="#1a1a1a")
        detail.attributes("-topmost", True)
        detail.after(200, lambda: detail.focus_force())

        proto_color = "#a78bfa" if sess.protocol == "HTTPS" else "#4ade80"
        ctk.CTkLabel(
            detail,
            text=f"{sess.protocol}  |  {sess.host or sess.remote_ip}:{sess.remote_port}",
            font=Fonts.title_medium, text_color=proto_color
        ).pack(pady=(15, 5), padx=15, anchor="w")

        if sess.alert:
            alert_colors = {"high": "#ef4444", "medium": "#f59e0b", "low": "#a78bfa"}
            ctk.CTkLabel(
                detail,
                text=f"ALERT [{sess.alert.upper()}]: " + " | ".join(sess.alert_reasons),
                font=Fonts.body_bold,
                text_color=alert_colors.get(sess.alert, "#9ca3af"),
                fg_color="#374151", corner_radius=6
            ).pack(pady=5, padx=15, fill="x")

        info_text = (
            f"Session ID: {sess.id}\n"
            f"Time: {sess.timestamp}\n"
            f"PID: {sess.pid}  Process: {sess.process_name}\n"
            f"Protocol: {sess.protocol}\n"
            f"Host: {sess.host or 'N/A'}\n"
            f"Remote: {sess.remote_ip}:{sess.remote_port}\n"
            f"Status: {sess.status}\n"
        )

        text_box = ctk.CTkTextbox(detail, fg_color="#1a1a1a", text_color="white",
                                   font=Fonts.body, wrap="word")
        text_box.pack(fill="both", expand=True, padx=15, pady=10)
        text_box.insert("1.0", info_text)
        text_box.configure(state="disabled")

        ctk.CTkButton(detail, text="Close", command=detail.destroy,
                      fg_color=self.colors["red"], hover_color=self.colors["red_dark"],
                      height=32, width=100).pack(pady=(0, 15))

    def _refresh_iocs_display(self):
        """Refresh IOCs display in the current case view."""
        current_case_view = self.app.views.get("current_case")
        if current_case_view and hasattr(current_case_view, 'refresh_iocs_display'):
            current_case_view.refresh_iocs_display()

    # ------------------------------------------------------------------
    # Quick Strings Panel methods
    # ------------------------------------------------------------------

    def _build_quick_strings_panel(self):
        """Build the collapsible Quick Strings panel (added to PanedWindow on demand)."""
        self._strings_panel = tk.Frame(self._process_paned, bg=self.colors["navy"])

        # Header bar
        header = tk.Frame(self._strings_panel, bg=self.colors["dark_blue"], height=36)
        header.pack(fill="x")
        header.pack_propagate(False)

        tk.Label(
            header, text="Quick Strings",
            bg=self.colors["dark_blue"], fg="#86efac",
            font=("Segoe UI", 12, "bold"),
        ).pack(side="left", padx=10)

        self._strings_status_lbl = tk.Label(
            header, text="Select a process",
            bg=self.colors["dark_blue"], fg="#9ca3af",
            font=("Segoe UI", 10),
        )
        self._strings_status_lbl.pack(side="left", padx=15)

        # Pop Out button
        tk.Button(
            header, text="Pop Out",
            bg=self.colors["dark_blue"], fg="white",
            activebackground=self.colors["red_dark"], activeforeground="white",
            relief="flat", bd=0, padx=8, font=("Segoe UI", 9),
            command=self._popout_strings_panel,
        ).pack(side="right", padx=5)

        # Close button
        tk.Button(
            header, text="Close",
            bg=self.colors["dark_blue"], fg="white",
            activebackground=self.colors["red_dark"], activeforeground="white",
            relief="flat", bd=0, padx=8, font=("Segoe UI", 9),
            command=self._toggle_quick_strings_panel,
        ).pack(side="right", padx=5)

        # The StringAnalysisPanel body
        body = ctk.CTkFrame(self._strings_panel, fg_color=self.colors["navy"])
        body.pack(fill="both", expand=True)

        self._strings_analysis = StringAnalysisPanel(
            parent=body,
            app=self.app,
            colors=self.colors,
            is_large_screen=self.is_large_screen,
            lightweight=True,
            max_per_category=200,
        )
        self._strings_analysis.frame.pack(fill="both", expand=True)

    def _toggle_quick_strings_panel(self):
        """Show or hide the Quick Strings panel in the PanedWindow."""
        if self._strings_panel_visible:
            self._process_paned.forget(self._strings_panel)
            self._strings_panel_visible = False
            self._strings_badge.configure(
                text="Strings \u25be",
                text_color="#9ca3af",
                fg_color="#374151", hover_color="#374151",
            )
        else:
            self._process_paned.add(self._strings_panel, stretch="always")
            self._process_paned.paneconfigure(self._strings_panel, height=280)
            self._strings_panel_visible = True
            self._strings_badge.configure(
                text="Strings \u25b4",
                text_color="#86efac",
                fg_color="#14532d", hover_color="#166534",
            )
            # If a process is selected, load its strings immediately
            if self._strings_selected_pid:
                self._load_strings_for_pid(self._strings_selected_pid)

    def _on_process_select_for_strings(self, event=None):
        """Update the Quick Strings panel when a process is selected."""
        sel = self.process_tree.selection()
        if not sel:
            self._strings_selected_pid = None
            return
        try:
            values = self.process_tree.item(sel[0], "values")
            pid = int(values[0])
            self._strings_selected_pid = pid
        except (ValueError, IndexError):
            self._strings_selected_pid = None
            return

        if self._strings_panel_visible:
            self._load_strings_for_pid(pid)

    def _load_strings_for_pid(self, pid: int):
        """Load strings for *pid* into the Quick Strings panel.

        Uses the cache if available (< 200ms), otherwise triggers a
        background quick scan.
        """
        import time

        # Check cache first
        if pid in self._strings_cache:
            ts, result = self._strings_cache[pid]
            if time.time() - ts < 30:
                self._strings_status_lbl.configure(
                    text=f"PID {pid} (cached)")
                self._strings_analysis.set_strings_data(result)
                return

        # Trigger background scan
        self._strings_status_lbl.configure(text=f"Scanning PID {pid}...")

        def _worker():
            try:
                extractor = getattr(self.app.process_monitor, 'memory_extractor', None)
                if not extractor:
                    self.root.after(
                        0,
                        lambda: self._strings_status_lbl.configure(
                            text="Memory extractor not available"),
                    )
                    return
                result = extractor.extract_strings_from_memory(
                    pid=pid,
                    min_length=4,
                    max_strings=500000,
                    include_unicode=True,
                    enable_quality_filter=True,
                    scan_mode="quick",
                    return_offsets=True,
                )
                self._strings_cache[pid] = (time.time(), result)
                self.root.after(0, lambda: self._on_strings_loaded(pid, result))
            except Exception as exc:
                self.root.after(
                    0,
                    lambda: self._strings_status_lbl.configure(
                        text=f"Error: {exc}"),
                )

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    def _on_strings_loaded(self, pid, result):
        """Called on the main thread when string extraction finishes."""
        if self._strings_selected_pid != pid:
            return  # user moved on
        self._strings_status_lbl.configure(text=f"PID {pid}")
        self._strings_analysis.set_strings_data(result)

    def _popout_strings_panel(self):
        """Open a full StringAnalysisPanel in a separate Toplevel window."""
        pid = self._strings_selected_pid
        if not pid:
            return

        # Close existing popout if any
        if self._strings_popout_window and self._strings_popout_window.winfo_exists():
            self._strings_popout_window.destroy()

        win = ctk.CTkToplevel(self.root)
        win.title(f"String Analysis - PID {pid}")
        win.geometry("1100x700")
        self._strings_popout_window = win

        panel = StringAnalysisPanel(
            parent=win,
            app=self.app,
            colors=self.colors,
            is_large_screen=self.is_large_screen,
            lightweight=False,
        )
        panel.frame.pack(fill="both", expand=True)

        # Load cached results if we have them, otherwise trigger scan
        import time
        if pid in self._strings_cache:
            ts, result = self._strings_cache[pid]
            if time.time() - ts < 60:
                panel.set_strings_data(result)
            else:
                panel.load_strings(pid, scan_mode="quick")
        else:
            panel.load_strings(pid, scan_mode="quick")

    # ------------------------------------------------------------------
    # Process context menu and actions
    # ------------------------------------------------------------------

    def show_process_context_menu(self, event):
        """Show right-click context menu for processes."""
        try:
            selection = self.process_tree.selection()
            if not selection:
                return

            item = self.process_tree.item(selection[0])
            pid = int(item['values'][0])
            is_suspended = False

            try:
                import psutil
                process_status = psutil.Process(pid).status()
                is_suspended = process_status == psutil.STATUS_STOPPED
            except:
                pass

            connections = self._get_process_connections(pid)
            if connections:
                self.process_context_menu.entryconfigure(4, state="normal")
            else:
                self.process_context_menu.entryconfigure(4, state="disabled")

            suspend_resume_idx = 6
            menu_length = self.process_context_menu.index('end')
            if menu_length is not None and menu_length >= suspend_resume_idx:
                try:
                    label = self.process_context_menu.entrycget(suspend_resume_idx, 'label')
                    if '⏸️' in label or '▶️' in label:
                        self.process_context_menu.delete(suspend_resume_idx)
                except:
                    pass

            if is_suspended:
                self.process_context_menu.insert_command(
                    suspend_resume_idx, label="▶️ Resume Process",
                    command=self.resume_selected_process)
            else:
                self.process_context_menu.insert_command(
                    suspend_resume_idx, label="⏸️ Suspend Process",
                    command=self.suspend_selected_process)

            self.process_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.process_context_menu.grab_release()

    def scan_selected_process(self):
        """Scan selected process with YARA."""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to scan")
            return

        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])

        def scan():
            result = self.app.process_monitor.scan_process(pid)
            if 'error' in result:
                self.root.after(0, lambda: messagebox.showerror("Scan Error", result['error']))
            else:
                matches_found = result.get('matches_found', False)
                rule = result.get('rule', 'No_YARA_Hit')
                threat_score = result.get('threat_score', 0)
                risk_level = result.get('risk_level', 'Low')
                strings = result.get('strings', [])

                if pid not in self.app.process_monitor.monitored_processes:
                    try:
                        proc = __import__('psutil').Process(pid)
                        self.app.process_monitor.monitored_processes[pid] = {
                            'pid': pid, 'name': proc.name(),
                            'exe': proc.exe() if proc.exe() else "N/A",
                            'scan_results': result,
                            'threat_detected': matches_found,
                            'yara_rule': rule if matches_found else None
                        }
                    except:
                        self.app.process_monitor.monitored_processes[pid] = {
                            'pid': pid, 'scan_results': result,
                            'threat_detected': matches_found,
                            'yara_rule': rule if matches_found else None
                        }
                else:
                    self.app.process_monitor.monitored_processes[pid]['scan_results'] = result
                    self.app.process_monitor.monitored_processes[pid]['threat_detected'] = matches_found
                    self.app.process_monitor.monitored_processes[pid]['yara_rule'] = rule if matches_found else None

                if matches_found and rule != 'No_YARA_Hit':
                    self.app.total_yara_matches += 1
                    self.root.after(0, self.update_yara_match_badge)

                    if not self.app.should_show_popup(rule):
                        self.root.after(0, self.refresh_process_list)
                        return

                    def show_threat_alert():
                        try:
                            proc = __import__('psutil').Process(pid)
                            proc_name = proc.name()
                            proc_exe = proc.exe() if proc.exe() else "N/A"
                        except:
                            proc_name = "Unknown"
                            proc_exe = "N/A"

                        alert = ctk.CTkToplevel(self.root)
                        alert.title("⚠️ Threat Detected")
                        alert.geometry("700x650")
                        alert.minsize(600, 500)
                        alert.attributes('-topmost', True)

                        main_frame = ctk.CTkFrame(alert, fg_color=self.colors["red_dark"])
                        main_frame.pack(fill="both", expand=True, padx=2, pady=2)

                        header_frame = ctk.CTkFrame(main_frame, fg_color=self.colors["red_dark"])
                        header_frame.pack(fill="x", padx=10, pady=(15, 10))

                        ctk.CTkLabel(header_frame, text="⚠️ MALICIOUS PROCESS DETECTED",
                                     font=Fonts.title_large, text_color="white").pack()

                        content_frame = ctk.CTkFrame(main_frame, fg_color=self.colors["red_dark"])
                        content_frame.pack(fill="both", expand=True, padx=10, pady=5)

                        all_rules = result.get('all_rules', [rule])
                        rules_display = ', '.join(all_rules) if len(all_rules) > 1 else rule

                        details_frame = ctk.CTkFrame(content_frame, fg_color="#1a1a1a", corner_radius=8)
                        details_frame.pack(fill="x", padx=10, pady=10)

                        details = (f"PID: {pid}\nName: {proc_name}\nPath: {proc_exe}\n\n"
                                   f"YARA Rule(s): {rules_display}\n"
                                   f"Threat Score: {threat_score}\nRisk Level: {risk_level}")

                        ctk.CTkLabel(details_frame, text=details, font=Fonts.body,
                                     justify="left", text_color="white").pack(pady=15, padx=15, anchor="w")

                        if strings:
                            ctk.CTkLabel(content_frame, text=f"Matched Strings ({len(strings)}):",
                                         font=Fonts.body_bold, text_color="white").pack(
                                             pady=(5, 5), padx=10, anchor="w")

                            strings_container = ctk.CTkFrame(content_frame, fg_color="#1a1a1a", corner_radius=8)
                            strings_container.pack(fill="both", expand=True, padx=10, pady=(0, 10))

                            strings_frame = ctk.CTkScrollableFrame(strings_container,
                                                                    fg_color="#2b2b2b", height=250)
                            strings_frame.pack(fill="both", expand=True, padx=5, pady=5)

                            for i, s in enumerate(strings, 1):
                                s_display = s[:100] + "..." if len(s) > 100 else s
                                ctk.CTkLabel(strings_frame, text=f"{i}. {s_display}",
                                             font=Fonts.helper, text_color="white",
                                             anchor="w", justify="left").pack(
                                                 anchor="w", pady=2, padx=5, fill="x")

                        footer_frame = ctk.CTkFrame(main_frame, fg_color=self.colors["red_dark"])
                        footer_frame.pack(fill="x", padx=10, pady=(5, 15))

                        ctk.CTkButton(footer_frame, text="Close", command=alert.destroy,
                                      fg_color=self.colors["navy"],
                                      hover_color=self.colors["dark_blue"],
                                      width=120, height=35).pack(pady=5)

                    self.root.after(0, show_threat_alert)
                else:
                    msg = f"PID {pid} Scan Complete\n\nNo threats detected."
                    self.root.after(0, lambda: messagebox.showinfo("Scan Results", msg))

                self.root.after(0, self.refresh_process_list)

        threading.Thread(target=scan, daemon=True).start()

    def scan_all_processes(self):
        """Scan all processes with YARA."""
        if not messagebox.askyesno("Confirm Scan All",
                                    "This will scan ALL running processes. This may take some time.\n\nContinue?"):
            return

        processes = self.app.process_monitor.get_all_processes()
        total_processes = len(processes)

        progress_window = ctk.CTkToplevel(self.root)
        progress_window.title("Scanning Processes")
        progress_window.geometry("500x200")
        progress_window.attributes('-topmost', True)

        frame = ctk.CTkFrame(progress_window, fg_color="gray20")
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        ctk.CTkLabel(frame, text="Scanning All Processes",
                     font=Fonts.title_medium, text_color="white").pack(pady=10)

        progress_label = ctk.CTkLabel(frame,
                                       text=f"Scanning process 0 of {total_processes}",
                                       font=Fonts.body, text_color="white")
        progress_label.pack(pady=10)

        progress_bar = ctk.CTkProgressBar(frame, width=400)
        progress_bar.pack(pady=10)
        progress_bar.set(0)

        stats_label = ctk.CTkLabel(frame,
                                    text="Threats found: 0 | Benign: 0 | Errors: 0",
                                    font=Fonts.helper, text_color="white")
        stats_label.pack(pady=10)

        scan_stats = {'scanned': 0, 'threats': 0, 'benign': 0, 'errors': 0}

        def scan_all():
            for i, proc in enumerate(processes):
                pid = proc['pid']
                self.root.after(0, lambda i=i: progress_label.configure(
                    text=f"Scanning PID {pid} ({i+1} of {total_processes})"))
                self.root.after(0, lambda i=i: progress_bar.set((i + 1) / total_processes))

                try:
                    result = self.app.process_monitor.scan_process(pid)
                    if 'error' not in result:
                        matches_found = result.get('matches_found', False)
                        rule = result.get('rule', 'No_YARA_Hit')

                        if pid not in self.app.process_monitor.monitored_processes:
                            self.app.process_monitor.monitored_processes[pid] = {
                                'pid': pid, 'name': proc['name'],
                                'exe': proc.get('exe', 'N/A'),
                                'scan_results': result,
                                'threat_detected': matches_found,
                                'yara_rule': rule if matches_found else None
                            }
                        else:
                            self.app.process_monitor.monitored_processes[pid]['scan_results'] = result
                            self.app.process_monitor.monitored_processes[pid]['threat_detected'] = matches_found
                            self.app.process_monitor.monitored_processes[pid]['yara_rule'] = rule if matches_found else None

                        if matches_found and rule != 'No_YARA_Hit':
                            scan_stats['threats'] += 1
                        else:
                            scan_stats['benign'] += 1
                    else:
                        scan_stats['errors'] += 1

                    scan_stats['scanned'] += 1
                    self.root.after(0, lambda: stats_label.configure(
                        text=f"Threats found: {scan_stats['threats']} | Benign: {scan_stats['benign']} | Errors: {scan_stats['errors']}"))
                except Exception as e:
                    scan_stats['errors'] += 1
                    print(f"[ERROR] Failed to scan PID {pid}: {e}")

            self.root.after(0, lambda: progress_label.configure(text="Scan Complete!"))
            self.root.after(0, self.refresh_process_list)

            summary_msg = (f"Scan Complete!\n\nTotal Scanned: {scan_stats['scanned']}\n"
                           f"Threats Detected: {scan_stats['threats']}\n"
                           f"Benign Processes: {scan_stats['benign']}\n"
                           f"Errors: {scan_stats['errors']}")
            self.root.after(0, lambda: messagebox.showinfo("Scan Complete", summary_msg))
            self.root.after(0, progress_window.destroy)

        threading.Thread(target=scan_all, daemon=True).start()

    def open_folder_location(self):
        """Open the folder containing the selected process's executable."""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to view")
            return

        item = self.process_tree.item(selection[0])
        file_path = item['values'][1]

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

    def kill_selected_process(self):
        """Kill selected process."""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to kill")
            return

        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])
        name = item['text'].strip()

        if messagebox.askyesno("Confirm Kill",
                               f"Are you sure you want to kill process {name} (PID {pid})?"):
            success = self.app.process_monitor.kill_process(pid)
            if success:
                messagebox.showinfo("Success", f"Process {pid} terminated")
                self.refresh_process_list()
            else:
                messagebox.showerror("Error", f"Failed to kill process {pid}")

    def suspend_selected_process(self):
        """Suspend/pause selected process."""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to suspend")
            return

        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])

        success = self.app.process_monitor.suspend_process(pid)
        if success:
            self.refresh_process_list()
        else:
            messagebox.showerror("Error", f"Failed to suspend process {pid}")

    def resume_selected_process(self):
        """Resume suspended process."""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to resume")
            return

        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])

        success = self.app.process_monitor.resume_process(pid)
        if success:
            messagebox.showinfo("Success", f"Process {pid} resumed")
            self.refresh_process_list()
        else:
            messagebox.showerror("Error", f"Failed to resume process {pid}")

    # ------------------------------------------------------------------
    # Connection IOC methods
    # ------------------------------------------------------------------

    def add_process_conn_ioc_to_case(self, field_type):
        """Add network connection IOCs from the selected process to the current case."""
        if not self.app.current_case:
            messagebox.showwarning("No Active Case",
                                    "No active case to add IOC to. Please create or load a case first.")
            return

        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process first.")
            return

        try:
            item = self.process_tree.item(selection[0])
            pid = int(item['values'][0])
            connections = self._get_process_connections(pid)

            if not connections:
                messagebox.showinfo("No Connections", f"No network connections found for PID {pid}.")
                return

            if field_type == "all_ips":
                added_ips = []
                for conn in connections:
                    rip = conn.get('remote_ip', '')
                    if rip and rip not in ('', '0.0.0.0', '::', '127.0.0.1', '::1'):
                        if rip not in added_ips:
                            self.app.case_manager.add_ioc("ips", rip)
                            added_ips.append(rip)
                if added_ips:
                    self._refresh_iocs_display()
                    messagebox.showinfo("Success",
                                        f"Added {len(added_ips)} IP(s) to case IOCs:\n" + "\n".join(added_ips))
                else:
                    messagebox.showinfo("No IPs", "No remote IPs found in this process's connections.")

            elif field_type == "remote_ip":
                remote_ips = []
                for conn in connections:
                    rip = conn.get('remote_ip', '')
                    if rip and rip not in ('', '0.0.0.0', '::', '127.0.0.1', '::1') and rip not in remote_ips:
                        remote_ips.append(rip)

                if not remote_ips:
                    messagebox.showinfo("No IPs", "No remote IPs found in this process's connections.")
                    return

                if len(remote_ips) == 1:
                    ip = remote_ips[0]
                    self.app.case_manager.add_ioc("ips", ip)
                    self._refresh_iocs_display()
                    messagebox.showinfo("Success", f"Added IP '{ip}' to case IOCs!")
                else:
                    self._show_connection_picker(remote_ips, "ips", "Select IP to Add")

            elif field_type == "hostname":
                hostnames = []
                for conn in connections:
                    hostname = conn.get('remote_hostname', '')
                    if hostname and hostname != '-' and hostname not in hostnames:
                        hostnames.append(hostname)

                if not hostnames:
                    messagebox.showinfo("No Hostnames",
                                        "No resolved hostnames found in this process's connections.")
                    return

                if len(hostnames) == 1:
                    domain = hostnames[0]
                    self.app.case_manager.add_ioc("domains", domain)
                    self._refresh_iocs_display()
                    messagebox.showinfo("Success", f"Added domain '{domain}' to case IOCs!")
                else:
                    self._show_connection_picker(hostnames, "domains", "Select Domain to Add")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to add IOC: {str(e)}")

    def _show_connection_picker(self, items, ioc_type, title):
        """Show a picker dialog for selecting which connection IOC to add to case."""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title(title)
        dialog.geometry("400x350")
        dialog.transient(self.root)
        dialog.grab_set()

        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (dialog.winfo_screenheight() // 2) - (350 // 2)
        dialog.geometry(f"400x350+{x}+{y}")

        content = ctk.CTkFrame(dialog, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=15)

        label = ctk.CTkLabel(content, text=f"Select {ioc_type.rstrip('s')} to add to case:",
                             font=("Segoe UI", 14, "bold"))
        label.pack(pady=(0, 10))

        scroll_frame = ctk.CTkScrollableFrame(content, fg_color="gray20", height=200)
        scroll_frame.pack(fill="both", expand=True, pady=(0, 10))

        check_vars = {}
        for item_val in items:
            var = tk.BooleanVar(value=True)
            check_vars[item_val] = var
            cb = ctk.CTkCheckBox(scroll_frame, text=item_val, variable=var,
                                 fg_color=self.colors["red"],
                                 hover_color=self.colors["red_dark"])
            cb.pack(anchor="w", padx=10, pady=3)

        def add_selected():
            added = []
            for val, var in check_vars.items():
                if var.get():
                    self.app.case_manager.add_ioc(ioc_type, val)
                    added.append(val)
            if added:
                self._refresh_iocs_display()
                messagebox.showinfo("Success",
                                    f"Added {len(added)} {ioc_type.rstrip('s')}(s) to case IOCs!")
            dialog.destroy()

        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(fill="x")

        ctk.CTkButton(btn_frame, text="Add Selected", command=add_selected,
                       fg_color=self.colors["red"], hover_color=self.colors["red_dark"],
                       height=35).pack(side="left", padx=5, expand=True, fill="x")
        ctk.CTkButton(btn_frame, text="Cancel", command=dialog.destroy,
                       fg_color="gray30", hover_color="gray40",
                       height=35).pack(side="right", padx=5)

    # ------------------------------------------------------------------
    # New process detection callback
    # ------------------------------------------------------------------

    def on_new_process_detected(self, proc_info):
        """Callback when new process is detected."""
        if not proc_info:
            return

        self.root.after(0, self.refresh_process_list)

        if proc_info.get('threat_detected'):
            scan_results = proc_info.get('scan_results', {})
            if not scan_results:
                return

            rule = scan_results.get('rule', 'Unknown')
            threat_score = scan_results.get('threat_score', 0)
            risk_level = scan_results.get('risk_level', 'Unknown')
            strings = scan_results.get('strings', [])

            self.app.total_yara_matches += 1
            self.root.after(0, self.update_yara_match_badge)

            if not self.app.should_show_popup(rule):
                return

            def show_alert():
                alert = ctk.CTkToplevel(self.root)
                alert.title("⚠️ Threat Detected")
                alert.geometry("700x650")
                alert.minsize(600, 500)
                alert.attributes('-topmost', True)

                main_frame = ctk.CTkFrame(alert, fg_color=self.colors["red_dark"])
                main_frame.pack(fill="both", expand=True, padx=2, pady=2)

                header_frame = ctk.CTkFrame(main_frame, fg_color=self.colors["red_dark"])
                header_frame.pack(fill="x", padx=10, pady=(15, 10))

                ctk.CTkLabel(header_frame, text="⚠️ MALICIOUS PROCESS DETECTED",
                             font=Fonts.title_large, text_color="white").pack()

                content_frame = ctk.CTkFrame(main_frame, fg_color=self.colors["red_dark"])
                content_frame.pack(fill="both", expand=True, padx=10, pady=5)

                all_rules = scan_results.get('all_rules', [rule])
                rules_display = ', '.join(all_rules) if len(all_rules) > 1 else rule

                details_frame = ctk.CTkFrame(content_frame, fg_color="#1a1a1a", corner_radius=8)
                details_frame.pack(fill="x", padx=10, pady=10)

                details = (f"PID: {proc_info['pid']}\nName: {proc_info['name']}\n"
                           f"Path: {proc_info['exe']}\n\n"
                           f"YARA Rule(s): {rules_display}\n"
                           f"Threat Score: {threat_score}\nRisk Level: {risk_level}")

                ctk.CTkLabel(details_frame, text=details, font=Fonts.body,
                             justify="left", text_color="white").pack(
                                 pady=15, padx=15, anchor="w")

                if strings:
                    ctk.CTkLabel(content_frame, text=f"Matched Strings ({len(strings)}):",
                                 font=Fonts.body_bold, text_color="white").pack(
                                     pady=(5, 5), padx=10, anchor="w")

                    strings_container = ctk.CTkFrame(content_frame, fg_color="#1a1a1a", corner_radius=8)
                    strings_container.pack(fill="both", expand=True, padx=10, pady=(0, 10))

                    strings_frame = ctk.CTkScrollableFrame(strings_container,
                                                            fg_color="#2b2b2b", height=250)
                    strings_frame.pack(fill="both", expand=True, padx=5, pady=5)

                    for i, s in enumerate(strings, 1):
                        s_display = s[:100] + "..." if len(s) > 100 else s
                        ctk.CTkLabel(strings_frame, text=f"{i}. {s_display}",
                                     font=Fonts.helper, text_color="white",
                                     anchor="w", justify="left").pack(
                                         anchor="w", pady=2, padx=5, fill="x")

                footer_frame = ctk.CTkFrame(main_frame, fg_color=self.colors["red_dark"])
                footer_frame.pack(fill="x", padx=10, pady=(5, 15))

                ctk.CTkButton(footer_frame, text="Close", command=alert.destroy,
                              fg_color=self.colors["navy"],
                              hover_color=self.colors["dark_blue"],
                              width=120, height=35).pack(pady=5)

            self.root.after(0, show_alert)

    # ------------------------------------------------------------------
    # Process details & strings window
    # ------------------------------------------------------------------

    def view_process_details_and_strings(self):
        """View detailed process information and extracted strings in a unified window."""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to view")
            return

        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])
        name = item['text'].strip()

        info = self.app.process_monitor.get_process_info(pid)
        if not info:
            messagebox.showerror("Error", f"Could not get info for PID {pid}")
            return

        details_window = ctk.CTkToplevel(self.root)
        details_window.title(f"Process Analysis: {name} (PID {pid})")
        details_window.geometry("1000x900")

        main_container = ctk.CTkFrame(details_window, fg_color=self.colors["dark_blue"])
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        header = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=60)
        header.pack(fill="x", padx=0, pady=(0, 10))
        header.pack_propagate(False)

        ctk.CTkLabel(header, text=f"🔍 {name} (PID {pid})",
                     font=Fonts.logo_subtitle).pack(side="left", padx=20, pady=15)

        # Tab buttons
        tab_frame = ctk.CTkFrame(main_container, fg_color="transparent")
        tab_frame.pack(fill="x", padx=0, pady=(0, 10))

        btn_info = ctk.CTkButton(
            tab_frame, text="📋 Process Info",
            command=lambda: show_tab("info"),
            height=35, width=150,
            fg_color=self.colors["red"], hover_color=self.colors["red_dark"])
        btn_info.pack(side="left", padx=5)

        btn_strings = ctk.CTkButton(
            tab_frame, text="📄 Strings",
            command=lambda: show_tab("strings"),
            height=35, width=150,
            fg_color="transparent", hover_color=self.colors["navy"],
            border_width=2, border_color=self.colors["red"])
        btn_strings.pack(side="left", padx=5)

        btn_events = ctk.CTkButton(
            tab_frame, text="📊 Live Events",
            command=lambda: show_tab("events"),
            height=35, width=150,
            fg_color="transparent", hover_color=self.colors["navy"],
            border_width=2, border_color=self.colors["red"])
        btn_events.pack(side="left", padx=5)

        content_area = ctk.CTkFrame(main_container, fg_color=self.colors["navy"])
        content_area.pack(fill="both", expand=True)

        # ===== INFO TAB =====
        info_frame = ctk.CTkFrame(content_area, fg_color="transparent")

        details_text = f"""Process Details (PID {pid})
{'='*80}

Name: {info.get('name', 'N/A')}
Executable: {info.get('exe', 'N/A')}
Command Line: {info.get('cmdline', 'N/A')}
Status: {info.get('status', 'N/A')}
Username: {info.get('username', 'N/A')}
Created: {info.get('create_time', 'N/A')}
Parent PID: {info.get('parent_pid', 'N/A')} ({info.get('parent_name', 'N/A')})

"""
        if 'cpu_percent' in info:
            details_text += f"CPU: {info['cpu_percent']:.1f}%\n"
        if 'memory_info' in info:
            details_text += f"Memory (RSS): {info['memory_info']['rss'] / 1024 / 1024:.2f} MB\n"
        if 'num_threads' in info:
            details_text += f"Threads: {info['num_threads']}\n"

        if info.get('connections'):
            details_text += f"\nNetwork Connections: {len(info['connections'])}\n"
            details_text += "=" * 80 + "\n"
            for conn in info['connections'][:10]:
                details_text += f"  {conn['laddr']} -> {conn['raddr']} ({conn['status']})\n"

        # YARA section
        yara_section = ""
        if pid in self.app.process_monitor.monitored_processes:
            scan_results = self.app.process_monitor.monitored_processes[pid].get('scan_results', {})
            if scan_results.get('matches_found'):
                yara_section += f"\n{'='*80}\n⚠️ YARA SCAN RESULTS\n{'='*80}\n"
                all_rules = scan_results.get('all_rules', [scan_results.get('rule', 'Unknown')])
                if len(all_rules) > 1:
                    yara_section += f"Rules Matched ({len(all_rules)}):\n"
                    for i, rule in enumerate(all_rules, 1):
                        yara_section += f"  {i}. {rule}\n"
                else:
                    yara_section += f"Rule Matched: {all_rules[0]}\n"
                yara_section += f"Threat Score: {scan_results.get('threat_score', 0)}\n"
                yara_section += f"Risk Level: {scan_results.get('risk_level', 'Unknown')}\n"
                if scan_results.get('strings'):
                    yara_section += f"\nMatched Strings ({len(scan_results['strings'])}):\n"
                    for i, s in enumerate(scan_results['strings'], 1):
                        yara_section += f"  {i}. {s}\n"

        # Sigma section
        sigma_section = ""
        if self.app.sigma_evaluator:
            exe = info.get('exe', '')
            if exe and exe != 'N/A':
                event_dict = {
                    'Image': exe,
                    'CommandLine': info.get('cmdline', exe),
                    'User': info.get('username', ''),
                    'ProcessId': str(pid),
                }
                try:
                    sigma_matches_full = self.app.sigma_evaluator._evaluate(event_dict, event_id=1)
                except Exception:
                    sigma_matches_full = []

                if sigma_matches_full:
                    sigma_section += f"\n{'='*80}\n🔷 SIGMA RULE MATCHES ({len(sigma_matches_full)})\n{'='*80}\n"
                    for i, match in enumerate(sigma_matches_full, 1):
                        rule = match.rule
                        level_icons = {'critical': '🔴', 'high': '🟠', 'medium': '🟡',
                                       'low': '🔵', 'informational': 'ℹ️'}
                        icon = level_icons.get(rule.level, '🔷')
                        sigma_section += f"\n{icon} Rule {i}: {rule.title}\n"
                        sigma_section += f"  Level: {rule.level.upper()}\n"
                        if rule.description:
                            sigma_section += f"  Description: {rule.description}\n"
                        if rule.tags:
                            sigma_section += f"  MITRE Tags: {', '.join(rule.tags)}\n"
                        if rule.falsepositives:
                            sigma_section += f"  False Positives: {', '.join(str(fp) for fp in rule.falsepositives)}\n"
                        if rule.references:
                            sigma_section += f"\n  References:\n"
                            for ref in rule.references:
                                sigma_section += f"    - {ref}\n"

        info_text_widget = tk.Text(
            info_frame, wrap="word", bg="#1a1a1a", fg="#ffffff",
            font=Fonts.monospace(11), relief="flat", padx=20, pady=20)

        info_text_widget.tag_configure("yara_section", foreground="#f87171")
        info_text_widget.tag_configure("sigma_section", foreground="#c084fc")

        info_text_widget.insert("1.0", details_text)
        if yara_section:
            yara_start = info_text_widget.index("end-1c")
            info_text_widget.insert("end", yara_section)
            info_text_widget.tag_add("yara_section", yara_start, info_text_widget.index("end-1c"))
        if sigma_section:
            sigma_start = info_text_widget.index("end-1c")
            info_text_widget.insert("end", sigma_section)
            info_text_widget.tag_add("sigma_section", sigma_start, info_text_widget.index("end-1c"))

        info_text_widget.configure(state="disabled")
        info_text_widget.pack(fill="both", expand=True, padx=2, pady=2)

        # ===== STRINGS TAB =====
        strings_frame = ctk.CTkFrame(content_area, fg_color="transparent")

        search_frame = ctk.CTkFrame(strings_frame, fg_color=self.colors["navy"], height=90)
        search_frame.pack(fill="x", padx=10, pady=10)
        search_frame.pack_propagate(False)

        search_row = ctk.CTkFrame(search_frame, fg_color="transparent")
        search_row.pack(fill="x", padx=5, pady=(5, 0))

        ctk.CTkLabel(search_row, text="🔍 Search:", font=Fonts.body_bold).pack(side="left", padx=(10, 5))

        search_entry = ctk.CTkEntry(search_row, width=300, height=35,
                                    placeholder_text="Enter search term...", font=Fonts.body)
        search_entry.pack(side="left", padx=5)

        status_label = ctk.CTkLabel(search_row, text="Extracting strings...",
                                    font=Fonts.helper, text_color="gray60")
        status_label.pack(side="left", padx=20)

        filter_row = ctk.CTkFrame(search_frame, fg_color="transparent")
        filter_row.pack(fill="x", padx=5, pady=(5, 5))

        ctk.CTkLabel(filter_row, text="📏 Length:", font=Fonts.body_bold).pack(side="left", padx=(10, 5))
        ctk.CTkLabel(filter_row, text="Min:", font=Fonts.helper).pack(side="left", padx=(5, 2))
        min_length_entry = ctk.CTkEntry(filter_row, width=60, height=30,
                                        placeholder_text="4", font=Fonts.helper)
        min_length_entry.insert(0, "4")
        min_length_entry.pack(side="left", padx=2)
        ctk.CTkLabel(filter_row, text="Max:", font=Fonts.helper).pack(side="left", padx=(10, 2))
        max_length_entry = ctk.CTkEntry(filter_row, width=60, height=30,
                                        placeholder_text="∞", font=Fonts.helper)
        max_length_entry.pack(side="left", padx=2)

        quality_filter_var = ctk.BooleanVar(value=True)
        quality_filter_checkbox = ctk.CTkCheckBox(
            filter_row, text="Quality Filter", variable=quality_filter_var,
            font=Fonts.helper, checkbox_width=20, checkbox_height=20)
        quality_filter_checkbox.pack(side="left", padx=15)

        quick_scan_btn = ctk.CTkButton(
            filter_row, text="⚡ Quick Scan", command=lambda: None,
            height=30, width=120, fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"], font=Fonts.label)
        quick_scan_btn.pack(side="left", padx=5)

        deep_scan_btn = ctk.CTkButton(
            filter_row, text="🔬 Deep Scan", command=lambda: None,
            height=30, width=120, fg_color="transparent",
            hover_color=self.colors["navy"], border_width=2,
            border_color=self.colors["red"], font=Fonts.label)
        deep_scan_btn.pack(side="left", padx=5)

        export_btn = ctk.CTkButton(
            filter_row, text="💾 Export TXT", command=lambda: None,
            height=30, width=120, fg_color="transparent",
            hover_color=self.colors["navy"], border_width=2,
            border_color=self.colors["red"], font=Fonts.label)
        export_btn.pack(side="left", padx=5)

        strings_text_frame = ctk.CTkFrame(strings_frame, fg_color="gray20")
        strings_text_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        str_vsb = tk.Scrollbar(strings_text_frame, orient="vertical", bg="#1a1a1a")
        str_vsb.pack(side="right", fill="y")
        str_hsb = tk.Scrollbar(strings_text_frame, orient="horizontal", bg="#1a1a1a")
        str_hsb.pack(side="bottom", fill="x")

        strings_text = tk.Text(
            strings_text_frame, wrap="none", bg="#1a1a1a", fg="#ffffff",
            font=Fonts.monospace(10), yscrollcommand=str_vsb.set,
            xscrollcommand=str_hsb.set)
        strings_text.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        str_vsb.config(command=strings_text.yview)
        str_hsb.config(command=strings_text.xview)

        all_strings_data = {"strings": [], "original_text": "",
                            "extraction_result": None, "current_mode": "quick"}

        def search_strings(event=None):
            try:
                if not details_window.winfo_exists():
                    return
            except:
                return

            search_term = search_entry.get().strip().lower()
            try:
                min_len = int(min_length_entry.get()) if min_length_entry.get() else 0
            except (ValueError, tk.TclError):
                min_len = 0
            try:
                max_len = int(max_length_entry.get()) if max_length_entry.get() else float('inf')
            except (ValueError, tk.TclError):
                max_len = float('inf')

            strings_text.configure(state="normal")
            strings_text.delete("1.0", "end")

            length_filtered = [s for s in all_strings_data["strings"] if min_len <= len(s) <= max_len]

            if not search_term:
                if length_filtered:
                    display_text = "\n".join(length_filtered[:1000])
                    strings_text.insert("1.0", display_text)
                    filter_msg = ""
                    if min_len > 0 or max_len < float('inf'):
                        filter_msg = f" (filtered by length: {min_len}-{max_len if max_len != float('inf') else '∞'})"
                    status_label.configure(text=f"Showing: {len(length_filtered)} strings{filter_msg}")
                else:
                    strings_text.insert("1.0", "No strings match the length filter")
                    status_label.configure(text="No matches")
            else:
                filtered = [s for s in length_filtered if search_term in s.lower()]
                if filtered:
                    for s in filtered[:1000]:
                        lower_s = s.lower()
                        start_idx = 0
                        strings_text.insert("end", s + "\n")
                        while True:
                            pos = lower_s.find(search_term, start_idx)
                            if pos == -1:
                                break
                            line_num = int(strings_text.index("end").split(".")[0]) - 1
                            tag_start = f"{line_num}.{pos}"
                            tag_end = f"{line_num}.{pos + len(search_term)}"
                            strings_text.tag_add("highlight", tag_start, tag_end)
                            start_idx = pos + len(search_term)

                    filter_msg = ""
                    if min_len > 0 or max_len < float('inf'):
                        filter_msg = f" (length: {min_len}-{max_len if max_len != float('inf') else '∞'})"
                    status_label.configure(text=f"Found: {len(filtered)} matches{filter_msg}")
                else:
                    strings_text.insert("1.0", f"No strings found matching '{search_term}' with current filters")
                    status_label.configure(text="No matches")

            strings_text.tag_config("highlight", background=self.colors["red"], foreground="white")
            strings_text.configure(state="disabled")

        search_entry.bind("<KeyRelease>", search_strings)
        min_length_entry.bind("<KeyRelease>", search_strings)
        max_length_entry.bind("<KeyRelease>", search_strings)

        def on_quality_filter_change():
            threading.Thread(target=lambda: extract(all_strings_data["current_mode"]), daemon=True).start()

        quality_filter_checkbox.configure(command=on_quality_filter_change)

        def extract(scan_mode="quick"):
            try:
                all_strings_data["current_mode"] = scan_mode
                if scan_mode == "quick":
                    self.root.after(0, lambda: quick_scan_btn.configure(
                        fg_color=self.colors["red"], text="⚡ Scanning..."))
                    self.root.after(0, lambda: deep_scan_btn.configure(
                        fg_color="transparent", text="🔬 Deep Scan"))
                else:
                    self.root.after(0, lambda: deep_scan_btn.configure(
                        fg_color=self.colors["red"], text="🔬 Scanning..."))
                    self.root.after(0, lambda: quick_scan_btn.configure(
                        fg_color="transparent", text="⚡ Quick Scan"))

                self.root.after(0, lambda: export_btn.configure(state="disabled"))
                status_label.configure(text=f"Extracting strings ({scan_mode} mode)...")

                try:
                    extract_min_length = int(min_length_entry.get()) if min_length_entry.get() else 4
                    extract_min_length = max(4, min(extract_min_length, 10))
                except ValueError:
                    extract_min_length = 4

                use_quality_filter = quality_filter_var.get()

                def progress_callback(current_strings, regions_total, regions_read, final=False):
                    try:
                        flat_strings = []
                        for category_strings in current_strings.values():
                            if isinstance(category_strings, list):
                                flat_strings.extend(category_strings)
                        status_msg = f"{scan_mode.capitalize()} scan: {len(flat_strings)} strings | {regions_read}/{regions_total} regions"
                        if final:
                            status_msg = f"Complete: {len(flat_strings)} strings ({scan_mode} mode)"
                        self.root.after(0, lambda msg=status_msg: status_label.configure(text=msg))
                        if final or regions_read % 10 == 0:
                            all_strings_data["strings"] = flat_strings
                            self.root.after(0, search_strings)
                    except Exception as e:
                        print(f"Progress callback error: {e}")

                extraction_result = self.app.process_monitor.extract_strings_from_process(
                    pid, min_length=extract_min_length, limit=20000,
                    enable_quality_filter=use_quality_filter,
                    scan_mode=scan_mode, progress_callback=progress_callback,
                    return_full_result=True)

                strings = extraction_result.get('strings', [])
                result_text = ""

                urls = [s for s in strings if ('http://' in s or 'https://' in s or 'www.' in s)]
                ips = [s for s in strings if any(c.isdigit() and '.' in s for c in s)]
                paths = [s for s in strings if ('\\' in s or '/' in s) and len(s) > 10]
                others = [s for s in strings if s not in urls and s not in ips and s not in paths]

                if urls:
                    result_text += f"URLs/Domains ({len(urls)}):\n" + "=" * 80 + "\n" + "\n".join(urls[:50]) + "\n\n"
                if ips:
                    result_text += f"IP Addresses ({len(ips)}):\n" + "=" * 80 + "\n" + "\n".join(ips[:50]) + "\n\n"
                if paths:
                    result_text += f"File Paths ({len(paths)}):\n" + "=" * 80 + "\n" + "\n".join(paths[:50]) + "\n\n"
                if others:
                    result_text += f"Other Strings ({len(others)}):\n" + "=" * 80 + "\n" + "\n".join(others[:200]) + "\n"

                all_strings_data["strings"] = strings
                all_strings_data["original_text"] = result_text
                all_strings_data["extraction_result"] = extraction_result

                filter_status = "Quality Filtered" if use_quality_filter else "All Strings (Unfiltered)"
                self.root.after(0, lambda: strings_text.configure(state="normal"))
                self.root.after(0, lambda: strings_text.delete("1.0", "end"))
                self.root.after(0, lambda: strings_text.insert("1.0", result_text))
                self.root.after(0, lambda: strings_text.configure(state="disabled"))
                self.root.after(0, lambda: status_label.configure(
                    text=f"Complete: {len(strings)} strings ({scan_mode} mode, {filter_status})"))

                if scan_mode == "quick":
                    self.root.after(0, lambda: quick_scan_btn.configure(
                        fg_color=self.colors["red"], text="⚡ Quick Scan"))
                else:
                    self.root.after(0, lambda: deep_scan_btn.configure(
                        fg_color=self.colors["red"], text="🔬 Deep Scan"))

                self.root.after(0, lambda: export_btn.configure(state="normal"))
                self.root.after(100, search_strings)

            except Exception as e:
                import traceback
                traceback.print_exc()
                self.root.after(0, lambda: strings_text.configure(state="normal"))
                self.root.after(0, lambda: strings_text.delete("1.0", "end"))
                self.root.after(0, lambda: strings_text.insert("1.0", f"Error: {str(e)}"))
                self.root.after(0, lambda: strings_text.configure(state="disabled"))
                self.root.after(0, lambda: status_label.configure(text="Error extracting strings"))
                if scan_mode == "quick":
                    self.root.after(0, lambda: quick_scan_btn.configure(text="⚡ Quick Scan"))
                else:
                    self.root.after(0, lambda: deep_scan_btn.configure(text="🔬 Deep Scan"))
                self.root.after(0, lambda: export_btn.configure(state="normal"))

        def export_strings():
            try:
                if not all_strings_data["strings"]:
                    messagebox.showwarning("No Strings",
                                            "No strings available to export. Please run a scan first.")
                    return

                default_name = f"{name}_{pid}_strings_{all_strings_data['current_mode']}.txt"
                file_path = filedialog.asksaveasfilename(
                    title="Export Strings", defaultextension=".txt",
                    initialfile=default_name,
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
                if not file_path:
                    return

                if all_strings_data.get("extraction_result"):
                    extraction_result = all_strings_data["extraction_result"]
                    if isinstance(extraction_result.get('strings'), list):
                        strings_list = extraction_result['strings']
                        extraction_result['strings'] = {
                            'ascii': strings_list, 'unicode': [],
                            'urls': [s for s in strings_list if 'http' in s or 'www.' in s],
                            'paths': [s for s in strings_list if '\\' in s or '/' in s],
                            'ips': [s for s in strings_list if any(c.isdigit() and '.' in s for c in s)],
                            'registry': [], 'environment': []
                        }
                    extraction_result['pid'] = pid
                else:
                    extraction_result = {
                        'pid': pid,
                        'strings': {
                            'ascii': all_strings_data["strings"], 'unicode': [],
                            'urls': [s for s in all_strings_data["strings"] if 'http' in s or 'www.' in s],
                            'paths': [s for s in all_strings_data["strings"] if '\\' in s or '/' in s],
                            'ips': [s for s in all_strings_data["strings"] if any(c.isdigit() and '.' in s for c in s)],
                            'registry': [], 'environment': []
                        },
                        'scan_mode': all_strings_data['current_mode'],
                        'memory_regions': [], 'total_bytes_scanned': 0,
                        'errors': ['Export created without full extraction metadata']
                    }

                if hasattr(self.app.process_monitor, 'memory_extractor') and self.app.process_monitor.memory_extractor:
                    success = self.app.process_monitor.memory_extractor.export_to_txt(
                        extraction_result, file_path, process_name=name)
                    if success:
                        network_copy_msg = ""
                        if self.app.current_case and self.app.current_case.get("network_case_path"):
                            try:
                                network_path = self.app.current_case["network_case_path"]
                                network_strings_path = os.path.join(network_path, os.path.basename(file_path))
                                shutil.copy2(file_path, network_strings_path)
                                network_copy_msg = f"\n\nAlso copied to network folder:\n{network_strings_path}"
                            except Exception as e:
                                print(f"Warning: Could not copy strings to network folder: {e}")

                        mem_regions = len(extraction_result.get('memory_regions', []))
                        bytes_scanned = extraction_result.get('total_bytes_scanned', 0)
                        summary = (f"Strings exported to:\n{file_path}\n\n"
                                   f"Memory Regions Scanned: {mem_regions}\n"
                                   f"Total Bytes Scanned: {bytes_scanned:,}\n"
                                   f"Extraction Method: {extraction_result.get('extraction_method', 'unknown')}"
                                   f"{network_copy_msg}")
                        messagebox.showinfo("Export Complete", summary)
                    else:
                        messagebox.showerror("Export Failed", "Failed to export strings")
                else:
                    messagebox.showerror("Export Failed", "Memory extractor not available")
            except Exception as e:
                messagebox.showerror("Export Error", f"Error exporting strings:\n{str(e)}")

        quick_scan_btn.configure(command=lambda: threading.Thread(
            target=lambda: extract("quick"), daemon=True).start())
        deep_scan_btn.configure(command=lambda: threading.Thread(
            target=lambda: extract("deep"), daemon=True).start())
        export_btn.configure(command=export_strings)

        threading.Thread(target=lambda: extract("quick"), daemon=True).start()

        # ===== LIVE EVENTS TAB =====
        events_frame = ctk.CTkFrame(content_area, fg_color="transparent")

        controls_frame = ctk.CTkFrame(events_frame, fg_color=self.colors["navy"], height=60)
        controls_frame.pack(fill="x", padx=10, pady=10)
        controls_frame.pack_propagate(False)

        monitor_btn_text = tk.StringVar(value="▶ Start Monitoring")
        monitor_btn = ctk.CTkButton(
            controls_frame, textvariable=monitor_btn_text, command=None,
            height=35, width=150, fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"])
        monitor_btn.pack(side="left", padx=10)

        evt_stats_label = ctk.CTkLabel(
            controls_frame,
            text="Total: 0 | File: 0 | Network: 0 | Thread: 0 | Process: 0",
            font=Fonts.helper, text_color="gray60")
        evt_stats_label.pack(side="left", padx=20)

        evt_export_btn = ctk.CTkButton(
            controls_frame, text="💾 Export", command=None,
            height=35, width=100, fg_color="transparent",
            border_width=2, border_color=self.colors["red"])
        evt_export_btn.pack(side="right", padx=10)

        evt_clear_btn = ctk.CTkButton(
            controls_frame, text="🗑 Clear", command=None,
            height=35, width=100, fg_color="transparent",
            border_width=2, border_color=self.colors["red"])
        evt_clear_btn.pack(side="right", padx=5)

        evt_filter_frame = ctk.CTkFrame(events_frame, fg_color=self.colors["navy"], height=50)
        evt_filter_frame.pack(fill="x", padx=10, pady=(0, 10))
        evt_filter_frame.pack_propagate(False)

        ctk.CTkLabel(evt_filter_frame, text="Filter:", font=Fonts.body_bold).pack(side="left", padx=10)

        filter_var = tk.StringVar(value="All")
        filter_types = ["All", "File", "Network", "Thread", "Process", "Registry"]
        for ftype in filter_types:
            btn = ctk.CTkButton(
                evt_filter_frame, text=ftype, command=None,
                height=30, width=80,
                fg_color="transparent" if ftype != "All" else self.colors["red"],
                hover_color=self.colors["navy"],
                border_width=1, border_color=self.colors["red"])
            btn.pack(side="left", padx=3)

        evt_tree_frame = ctk.CTkFrame(events_frame, fg_color="gray20")
        evt_tree_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        evt_tree_vsb = tk.Scrollbar(evt_tree_frame, orient="vertical", bg="#1a1a1a")
        evt_tree_vsb.pack(side="right", fill="y")
        evt_tree_hsb = tk.Scrollbar(evt_tree_frame, orient="horizontal", bg="#1a1a1a")
        evt_tree_hsb.pack(side="bottom", fill="x")

        evt_columns = ("time", "type", "operation", "path", "result")
        events_tree = ttk.Treeview(
            evt_tree_frame, columns=evt_columns, show="headings", height=20,
            yscrollcommand=evt_tree_vsb.set, xscrollcommand=evt_tree_hsb.set)

        events_tree.heading("time", text="Time")
        events_tree.heading("type", text="Type")
        events_tree.heading("operation", text="Operation")
        events_tree.heading("path", text="Path")
        events_tree.heading("result", text="Result")
        events_tree.column("time", width=100, minwidth=100)
        events_tree.column("type", width=80, minwidth=80)
        events_tree.column("operation", width=150, minwidth=100)
        events_tree.column("path", width=400, minwidth=200)
        events_tree.column("result", width=100, minwidth=80)

        events_tree.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        evt_tree_vsb.config(command=events_tree.yview)
        evt_tree_hsb.config(command=events_tree.xview)

        event_monitor_state = {
            "monitor": None, "monitoring": False,
            "filter": "All", "update_job": None
        }

        def toggle_monitoring():
            if not event_monitor_state["monitoring"]:
                try:
                    monitor = ProcmonLiveMonitor(pid, max_events=5000)
                    monitor.start_monitoring()
                    self.app.procmon_monitors[pid] = monitor
                    event_monitor_state["monitor"] = monitor
                    event_monitor_state["monitoring"] = True
                    monitor_btn_text.set("⏸ Stop Monitoring")
                    monitor_btn.configure(fg_color="#059669")
                    refresh_events()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to start monitoring: {str(e)}")
            else:
                if event_monitor_state["monitor"]:
                    event_monitor_state["monitor"].stop_monitoring()
                    if pid in self.app.procmon_monitors:
                        del self.app.procmon_monitors[pid]
                event_monitor_state["monitoring"] = False
                event_monitor_state["monitor"] = None
                monitor_btn_text.set("▶ Start Monitoring")
                monitor_btn.configure(fg_color=self.colors["red"])
                if event_monitor_state["update_job"]:
                    details_window.after_cancel(event_monitor_state["update_job"])
                    event_monitor_state["update_job"] = None

        def refresh_events():
            if not event_monitor_state["monitoring"] or not event_monitor_state["monitor"]:
                return
            try:
                monitor = event_monitor_state["monitor"]
                filter_type = event_monitor_state["filter"]
                events = monitor.get_recent_events(
                    count=1000, event_type=None if filter_type == "All" else filter_type)

                events_tree.delete(*events_tree.get_children())
                for event in events:
                    events_tree.insert("", "end", values=(
                        event['timestamp'], event['event_type'],
                        event['operation'],
                        event['path'][:80] + "..." if len(event['path']) > 80 else event['path'],
                        event['result']))

                stats = monitor.get_stats()
                evt_stats_label.configure(
                    text=f"Total: {stats['total_events']} | "
                         f"File: {stats['file_events']} | "
                         f"Network: {stats['network_events']} | "
                         f"Thread: {stats['thread_events']} | "
                         f"Process: {stats['process_events']}")

                event_monitor_state["update_job"] = details_window.after(500, refresh_events)
            except Exception as e:
                print(f"Error refreshing events: {e}")

        def export_events():
            if not event_monitor_state["monitor"]:
                messagebox.showwarning("No Data", "No events to export. Start monitoring first.")
                return
            filepath = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                initialfile=f"procmon_events_pid_{pid}.csv")
            if filepath:
                try:
                    event_monitor_state["monitor"].export_events(filepath)
                    messagebox.showinfo("Success", f"Events exported to {filepath}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to export: {str(e)}")

        def clear_events():
            if event_monitor_state["monitor"]:
                event_monitor_state["monitor"].clear_events()
                events_tree.delete(*events_tree.get_children())
                evt_stats_label.configure(
                    text="Total: 0 | File: 0 | Network: 0 | Thread: 0 | Process: 0")

        def set_filter(ftype):
            event_monitor_state["filter"] = ftype
            for widget in evt_filter_frame.winfo_children():
                if isinstance(widget, ctk.CTkButton) and widget.cget("text") in filter_types:
                    if widget.cget("text") == ftype:
                        widget.configure(fg_color=self.colors["red"])
                    else:
                        widget.configure(fg_color="transparent")
            refresh_events()

        monitor_btn.configure(command=toggle_monitoring)
        evt_export_btn.configure(command=export_events)
        evt_clear_btn.configure(command=clear_events)

        for widget in evt_filter_frame.winfo_children():
            if isinstance(widget, ctk.CTkButton) and widget.cget("text") in filter_types:
                ftype = widget.cget("text")
                widget.configure(command=lambda f=ftype: set_filter(f))

        def on_window_close():
            if event_monitor_state["monitoring"]:
                toggle_monitoring()
            details_window.destroy()

        details_window.protocol("WM_DELETE_WINDOW", on_window_close)

        # Tab switching
        tabs = {"info": info_frame, "strings": strings_frame, "events": events_frame}
        buttons = {"info": btn_info, "strings": btn_strings, "events": btn_events}

        def show_tab(tab_name):
            for n, f in tabs.items():
                f.pack_forget()
            for n, b in buttons.items():
                if n == tab_name:
                    b.configure(fg_color=self.colors["red"], border_width=0)
                else:
                    b.configure(fg_color="transparent", border_width=2,
                                border_color=self.colors["red"])
            tabs[tab_name].pack(fill="both", expand=True)
            if tab_name == "events" and not event_monitor_state["monitoring"]:
                toggle_monitoring()

        show_tab("info")
