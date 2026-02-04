"""
Processes Subtab
Real-time process monitoring and analysis interface.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING

from typography import Fonts
from ui.theme import Theme

if TYPE_CHECKING:
    from ui.app import ForensicAnalysisGUI


class ProcessesSubtab:
    """Subtab for process monitoring and analysis"""

    def __init__(self, app: 'ForensicAnalysisGUI', parent: ctk.CTkFrame):
        self.app = app
        self.parent = parent
        self.colors = app.colors
        self.frame = None

        # UI elements
        self.process_tree = None
        self.process_context_menu = None
        self.btn_toggle_monitor = None
        self.process_search_entry = None
        self.process_filter_var = None
        self.process_filter_dropdown = None
        self.yara_match_badge = None

    def create(self) -> ctk.CTkFrame:
        """Create Processes sub-tab with optimized tree view"""
        self.frame = ctk.CTkFrame(self.parent, fg_color="transparent")

        # Header with controls
        header = ctk.CTkFrame(self.frame, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=10)

        title = ctk.CTkLabel(
            header, text="Process Analysis",
            font=Fonts.title_large,
            text_color="white"
        )
        title.pack(side="left")

        # Monitor toggle
        self.btn_toggle_monitor = ctk.CTkButton(
            header, text="▶ Start Monitoring",
            command=self.app.toggle_process_monitoring,
            height=35, width=150,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"]
        )
        self.btn_toggle_monitor.pack(side="right", padx=5)

        # Scan All button
        btn_scan_all = ctk.CTkButton(
            header, text="🔍 Scan All",
            command=self.app.scan_all_processes,
            height=35, width=100,
            fg_color="#8B4513",
            hover_color="#A0522D"
        )
        btn_scan_all.pack(side="right", padx=5)

        # Refresh button
        btn_refresh = ctk.CTkButton(
            header, text="🔄 Refresh",
            command=self.app.refresh_process_list,
            height=35, width=100,
            fg_color=self.colors["navy"],
            hover_color=self.colors["dark_blue"]
        )
        btn_refresh.pack(side="right", padx=5)

        # Search bar
        self._create_search_bar()

        # Process tree
        self._create_process_tree()

        # Context menu
        self._create_context_menu()

        # Store references in app for backward compatibility
        self.app.btn_toggle_process_monitor = self.btn_toggle_monitor
        self.app.process_tree = self.process_tree
        self.app.process_context_menu = self.process_context_menu
        self.app.process_search_entry = self.process_search_entry
        self.app.process_filter_var = self.process_filter_var
        self.app.process_filter_dropdown = self.process_filter_dropdown
        self.app.yara_match_badge = self.yara_match_badge

        # Initial load
        self.app.refresh_process_list()

        return self.frame

    def _create_search_bar(self):
        """Create search and filter controls"""
        search_frame = ctk.CTkFrame(self.frame, fg_color="transparent")
        search_frame.pack(fill="x", padx=20, pady=(0, 10))

        search_label = ctk.CTkLabel(
            search_frame, text="🔍 Search:",
            font=Fonts.body,
            text_color="white"
        )
        search_label.pack(side="left", padx=(0, 10))

        self.process_search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="Enter PID or Process Name...",
            height=35,
            width=300,
            fg_color="gray20",
            border_color=self.colors["navy"],
            border_width=2
        )
        self.process_search_entry.pack(side="left", padx=5)
        self.process_search_entry.bind("<KeyRelease>", lambda e: self.app.filter_processes())

        # Clear search button
        btn_clear_search = ctk.CTkButton(
            search_frame, text="✕ Clear",
            command=self.app.clear_process_search,
            height=35, width=80,
            fg_color="gray30",
            hover_color="gray40"
        )
        btn_clear_search.pack(side="left", padx=5)

        # Filter dropdown
        filter_label = ctk.CTkLabel(
            search_frame, text="Filter:",
            font=Fonts.body,
            text_color="white"
        )
        filter_label.pack(side="left", padx=(20, 10))

        self.process_filter_var = ctk.StringVar(value="All Processes")
        self.process_filter_dropdown = ctk.CTkComboBox(
            search_frame,
            values=["All Processes", "YARA Matches Only", "Benign Only", "Not Scanned"],
            variable=self.process_filter_var,
            command=lambda choice: self.app.filter_processes(),
            height=35,
            width=180,
            fg_color="gray20",
            border_color=self.colors["navy"],
            button_color=self.colors["navy"],
            button_hover_color=self.colors["dark_blue"]
        )
        self.process_filter_dropdown.pack(side="left", padx=5)

        # YARA match counter badge
        self.yara_match_badge = ctk.CTkLabel(
            search_frame,
            text="⚠️ YARA: 0",
            font=("Segoe UI", 13, "bold"),
            text_color="#fbbf24",
            fg_color="#78350f",
            corner_radius=6,
            padx=12,
            pady=6
        )
        self.yara_match_badge.pack(side="left", padx=(15, 5))

    def _create_process_tree(self):
        """Create the process tree view"""
        tree_frame = ctk.CTkFrame(self.frame, fg_color="gray20")
        tree_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Scrollbars
        vsb = tk.Scrollbar(tree_frame, orient="vertical", bg="#1a1a1a", troughcolor="#0d1520")
        hsb = tk.Scrollbar(tree_frame, orient="horizontal", bg="#1a1a1a", troughcolor="#0d1520")
        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")

        # Style for Treeview
        style = ttk.Style()
        style.theme_use('default')

        style.configure("Process.Treeview",
                        background="#1a1a1a",
                        foreground="white",
                        fieldbackground="#1a1a1a",
                        borderwidth=0,
                        relief="flat")

        style.configure("Process.Treeview.Heading",
                        background="#0d1520",
                        foreground="white",
                        borderwidth=1,
                        relief="flat")

        style.map("Process.Treeview",
                  background=[('selected', '#dc2626')],
                  foreground=[('selected', 'white')])

        style.map("Process.Treeview.Heading",
                  background=[('active', '#1a2332')])

        # Treeview with hierarchy support
        columns = ("PID", "Name", "File Path", "YARA Matches")
        self.process_tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="tree headings",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
            style="Process.Treeview"
        )
        self.process_tree.pack(side="left", fill="both", expand=True)
        vsb.config(command=self.process_tree.yview)
        hsb.config(command=self.process_tree.xview)

        # Configure columns
        self.process_tree.column("#0", width=200, minwidth=150)
        self.process_tree.column("PID", width=80, minwidth=60, anchor="center")
        self.process_tree.column("Name", width=200, minwidth=150)
        self.process_tree.column("File Path", width=350, minwidth=200)
        self.process_tree.column("YARA Matches", width=150, minwidth=100, anchor="center")

        # Headers
        self.process_tree.heading("#0", text="Process Tree")
        self.process_tree.heading("PID", text="PID")
        self.process_tree.heading("Name", text="Name")
        self.process_tree.heading("File Path", text="File Path")
        self.process_tree.heading("YARA Matches", text="YARA Matches")

        # Configure tag colors
        self.process_tree.tag_configure('threat', background='#5c1c1c', foreground='white')
        self.process_tree.tag_configure('new', background='#8B7500', foreground='white')
        self.process_tree.tag_configure('benign', background='#1a4d2e', foreground='white')
        self.process_tree.tag_configure('system', foreground='#888888')
        self.process_tree.tag_configure('suspended', background='#3a3a3a', foreground='#808080')

        # Bind events
        self.process_tree.bind("<Button-3>", self.app.show_process_context_menu)
        self.process_tree.bind("<Double-1>", lambda e: self.app.view_process_details_and_strings())

    def _create_context_menu(self):
        """Create right-click context menu"""
        menu_config = Theme.get_menu_config()
        self.process_context_menu = tk.Menu(self.process_tree, tearoff=0, **menu_config)

        self.process_context_menu.add_command(
            label="🔍 Scan with YARA",
            command=self.app.scan_selected_process
        )
        self.process_context_menu.add_command(
            label="📋 View Details & Strings",
            command=self.app.view_process_details_and_strings
        )
        self.process_context_menu.add_command(
            label="📂 Open Folder Location",
            command=self.app.open_folder_location
        )
        self.process_context_menu.add_separator(background="#444444")
        self.process_context_menu.add_command(
            label="❌ Kill Process",
            command=self.app.kill_selected_process
        )

    def show(self):
        """Show this subtab"""
        self.frame.pack(fill="both", expand=True)

    def hide(self):
        """Hide this subtab"""
        self.frame.pack_forget()

    def on_show(self):
        """Called when subtab is shown"""
        pass
