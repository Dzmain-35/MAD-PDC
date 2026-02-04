"""
Analysis Tab
Container tab for analysis subtabs (Processes, Network, Live Events).
"""

import customtkinter as ctk
from typing import TYPE_CHECKING

from typography import Fonts
from .base_tab import BaseTab
from .analysis import ProcessesSubtab, NetworkSubtab, LiveEventsSubtab

if TYPE_CHECKING:
    from ui.app import ForensicAnalysisGUI


class AnalysisTab(BaseTab):
    """Container tab for analysis subtabs"""

    def __init__(self, app: 'ForensicAnalysisGUI', parent: ctk.CTkFrame):
        super().__init__(app, parent)
        self.subtabs = {}
        self.subtab_buttons = {}
        self.current_subtab = None
        self.analysis_content = None

    def create(self) -> ctk.CTkFrame:
        """Create the Analysis tab with sub-tabs"""
        self.frame = ctk.CTkFrame(self.parent, fg_color=self.colors["dark_blue"])

        title = ctk.CTkLabel(
            self.frame, text="Analysis",
            font=Fonts.header_main,
            text_color="white"
        )
        title.pack(pady=20, padx=20, anchor="w")

        # Sub-tab buttons
        subtab_frame = ctk.CTkFrame(self.frame, fg_color="transparent")
        subtab_frame.pack(fill="x", padx=20, pady=10)

        self.btn_processes = ctk.CTkButton(
            subtab_frame, text="⚙️ Processes",
            command=lambda: self.show_subtab("processes"),
            height=35, width=150,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            font=Fonts.body_bold
        )
        self.btn_processes.pack(side="left", padx=5)
        self.subtab_buttons["processes"] = self.btn_processes

        self.btn_network = ctk.CTkButton(
            subtab_frame, text="🌐 Network",
            command=lambda: self.show_subtab("network"),
            height=35, width=150,
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["red"],
            font=Fonts.body_bold
        )
        self.btn_network.pack(side="left", padx=5)
        self.subtab_buttons["network"] = self.btn_network

        self.btn_live_events = ctk.CTkButton(
            subtab_frame, text="📡 Live Events",
            command=lambda: self.show_subtab("live_events"),
            height=35, width=150,
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["red"],
            font=Fonts.body_bold
        )
        self.btn_live_events.pack(side="left", padx=5)
        self.subtab_buttons["live_events"] = self.btn_live_events

        # Content area for sub-tabs
        self.analysis_content = ctk.CTkFrame(
            self.frame, corner_radius=10, fg_color=self.colors["navy"]
        )
        self.analysis_content.pack(fill="both", expand=True, padx=20, pady=10)

        # Create sub-tabs
        self._create_subtabs()

        # Show initial subtab
        self.show_subtab("processes")

        # Store references in app for backward compatibility
        self.app.btn_processes = self.btn_processes
        self.app.btn_network = self.btn_network
        self.app.btn_live_events = self.btn_live_events
        self.app.analysis_content = self.analysis_content
        self.app.analysis_subtabs = {
            name: subtab.frame for name, subtab in self.subtabs.items()
        }

        return self.frame

    def _create_subtabs(self):
        """Create all analysis subtabs"""
        # Processes subtab
        processes = ProcessesSubtab(self.app, self.analysis_content)
        processes.create()
        self.subtabs["processes"] = processes

        # Network subtab
        network = NetworkSubtab(self.app, self.analysis_content)
        network.create()
        self.subtabs["network"] = network

        # Live events subtab
        live_events = LiveEventsSubtab(self.app, self.analysis_content)
        live_events.create()
        self.subtabs["live_events"] = live_events

    def show_subtab(self, subtab_name: str):
        """Switch between analysis sub-tabs"""
        # Hide all subtabs
        for subtab in self.subtabs.values():
            subtab.hide()

        # Reset all button colors
        for btn in self.subtab_buttons.values():
            btn.configure(
                fg_color="transparent",
                border_width=2,
                border_color=self.colors["red"]
            )

        # Show selected subtab
        if subtab_name in self.subtabs:
            self.subtabs[subtab_name].show()
            self.current_subtab = subtab_name

            # Highlight button
            if subtab_name in self.subtab_buttons:
                self.subtab_buttons[subtab_name].configure(
                    fg_color=self.colors["red"],
                    border_width=0
                )

            # Trigger on_show for the subtab
            self.subtabs[subtab_name].on_show()

    def on_show(self):
        """Called when the analysis tab is shown"""
        # Refresh current subtab if exists
        if self.current_subtab and self.current_subtab in self.subtabs:
            self.subtabs[self.current_subtab].on_show()
