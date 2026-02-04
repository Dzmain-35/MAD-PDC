"""
Network Subtab
Network connection monitoring interface.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk
from typing import TYPE_CHECKING

from typography import Fonts
from ui.theme import Theme

if TYPE_CHECKING:
    from ui.app import ForensicAnalysisGUI


class NetworkSubtab:
    """Subtab for network monitoring"""

    def __init__(self, app: 'ForensicAnalysisGUI', parent: ctk.CTkFrame):
        self.app = app
        self.parent = parent
        self.colors = app.colors
        self.frame = None

        # UI elements
        self.network_tree = None
        self.network_context_menu = None
        self.btn_toggle_monitor = None
        self.network_stats_label = None

    def create(self) -> ctk.CTkFrame:
        """Create Network sub-tab"""
        self.frame = ctk.CTkFrame(self.parent, fg_color="transparent")

        # Header
        header = ctk.CTkFrame(self.frame, fg_color="transparent")
        header.pack(fill="x", padx=20, pady=10)

        title = ctk.CTkLabel(
            header, text="Network Analysis",
            font=Fonts.title_large,
            text_color="white"
        )
        title.pack(side="left")

        # Monitor toggle
        self.btn_toggle_monitor = ctk.CTkButton(
            header, text="▶ Start Monitoring",
            command=self.app.toggle_network_monitoring,
            height=35, width=150,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"]
        )
        self.btn_toggle_monitor.pack(side="right", padx=5)

        # Refresh button
        btn_refresh = ctk.CTkButton(
            header, text="🔄 Refresh",
            command=self.app.refresh_network_list,
            height=35, width=100,
            fg_color=self.colors["navy"],
            hover_color=self.colors["dark_blue"]
        )
        btn_refresh.pack(side="right", padx=5)

        # Stats frame
        stats_frame = ctk.CTkFrame(self.frame, fg_color="gray20", corner_radius=10)
        stats_frame.pack(fill="x", padx=20, pady=10)

        self.network_stats_label = ctk.CTkLabel(
            stats_frame,
            text="Network Statistics: Not monitoring",
            font=Fonts.helper,
            justify="left"
        )
        self.network_stats_label.pack(padx=15, pady=10, anchor="w")

        # Connection list
        self._create_network_tree()

        # Context menu
        self._create_context_menu()

        # Store references in app for backward compatibility
        self.app.btn_toggle_network_monitor = self.btn_toggle_monitor
        self.app.network_tree = self.network_tree
        self.app.network_context_menu = self.network_context_menu
        self.app.network_stats_label = self.network_stats_label

        return self.frame

    def _create_network_tree(self):
        """Create the network connections tree view"""
        tree_frame = ctk.CTkFrame(self.frame, fg_color="gray20")
        tree_frame.pack(fill="both", expand=True, padx=20, pady=10)

        vsb = tk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side="right", fill="y")

        columns = ("Type", "Local", "Remote", "Hostname", "Status", "Process", "Suspicious")
        self.network_tree = ttk.Treeview(
            tree_frame, columns=columns,
            show="headings", yscrollcommand=vsb.set
        )
        self.network_tree.pack(side="left", fill="both", expand=True)
        vsb.config(command=self.network_tree.yview)

        # Configure columns
        self.network_tree.heading("Type", text="Type")
        self.network_tree.column("Type", width=80, minwidth=60)
        self.network_tree.heading("Local", text="Local")
        self.network_tree.column("Local", width=150, minwidth=100)
        self.network_tree.heading("Remote", text="Remote")
        self.network_tree.column("Remote", width=150, minwidth=100)
        self.network_tree.heading("Hostname", text="Hostname")
        self.network_tree.column("Hostname", width=200, minwidth=120)
        self.network_tree.heading("Status", text="Status")
        self.network_tree.column("Status", width=100, minwidth=80)
        self.network_tree.heading("Process", text="Process")
        self.network_tree.column("Process", width=150, minwidth=100)
        self.network_tree.heading("Suspicious", text="Suspicious")
        self.network_tree.column("Suspicious", width=80, minwidth=60)

        # Configure tag colors
        self.network_tree.tag_configure('suspicious', background='#5c1c1c')

        # Bind right-click
        self.network_tree.bind("<Button-3>", self.app.show_network_context_menu)

    def _create_context_menu(self):
        """Create right-click context menu"""
        menu_config = Theme.get_menu_config()
        self.network_context_menu = tk.Menu(self.network_tree, tearoff=0, **menu_config)

        self.network_context_menu.add_command(
            label="📋 Copy Local Address",
            command=lambda: self.app.copy_network_cell(1)
        )
        self.network_context_menu.add_command(
            label="📋 Copy Remote Address",
            command=lambda: self.app.copy_network_cell(2)
        )
        self.network_context_menu.add_command(
            label="📋 Copy Hostname",
            command=lambda: self.app.copy_network_cell(3)
        )
        self.network_context_menu.add_command(
            label="📋 Copy Process Name",
            command=lambda: self.app.copy_network_cell(5)
        )
        self.network_context_menu.add_separator(background="#444444")
        self.network_context_menu.add_command(
            label="📋 Copy Entire Row",
            command=self.app.copy_network_row
        )
        self.network_context_menu.add_separator(background="#444444")
        self.network_context_menu.add_command(
            label="➕ Add Remote IP to IOCs",
            command=lambda: self.app.add_network_ioc_to_case("remote_ip")
        )
        self.network_context_menu.add_command(
            label="➕ Add Hostname to IOCs",
            command=lambda: self.app.add_network_ioc_to_case("hostname")
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
