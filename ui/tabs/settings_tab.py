"""
Settings Tab
Application settings configuration interface.
"""

import customtkinter as ctk
from tkinter import messagebox
from typing import TYPE_CHECKING, Dict, Any, Optional

from typography import Fonts
from .base_tab import BaseTab

if TYPE_CHECKING:
    from ui.app import ForensicAnalysisGUI


class SettingsTab(BaseTab):
    """Tab for application settings"""

    def __init__(self, app: 'ForensicAnalysisGUI', parent: ctk.CTkFrame):
        super().__init__(app, parent)
        self.settings_widgets: Dict[str, Any] = {}

    def create(self) -> ctk.CTkFrame:
        """Create the Settings tab"""
        self.frame = ctk.CTkFrame(self.parent, fg_color=self.colors["dark_blue"])

        # Header
        header_frame = ctk.CTkFrame(self.frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=20)

        title = ctk.CTkLabel(
            header_frame, text="Application Settings",
            font=Fonts.header_subsection,
            text_color="white"
        )
        title.pack(side="left")

        # Action buttons
        btn_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        btn_frame.pack(side="right")

        btn_save = ctk.CTkButton(
            btn_frame, text="Save Settings",
            command=self.save_settings,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            font=Fonts.label_large
        )
        btn_save.pack(side="left", padx=5)

        btn_reset = ctk.CTkButton(
            btn_frame, text="Reset to Defaults",
            command=self.reset_settings,
            fg_color=self.colors["navy"],
            hover_color=self.colors["dark_blue"],
            font=Fonts.label_large
        )
        btn_reset.pack(side="left", padx=5)

        # Scrollable settings container
        settings_scroll = ctk.CTkScrollableFrame(self.frame, fg_color="transparent")
        settings_scroll.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Create settings sections
        self._create_section(settings_scroll, "API Keys", [
            ("api_keys.virustotal", "VirusTotal API Key", "entry"),
            ("api_keys.threathq_user", "ThreatHQ Username", "entry"),
            ("api_keys.threathq_pass", "ThreatHQ Password", "entry"),
        ])

        self._create_section(settings_scroll, "Analysis Settings", [
            ("analysis.enable_process_monitoring", "Enable Process Monitoring", "switch"),
            ("analysis.enable_network_monitoring", "Enable Network Monitoring", "switch"),
            ("analysis.enable_yara_scanning", "Enable YARA Scanning", "switch"),
            ("analysis.auto_scan_new_processes", "Auto-scan New Processes", "switch"),
            ("analysis.enable_realtime_alerts", "Enable Real-time Alerts", "switch"),
        ])

        self._create_section(settings_scroll, "User Interface", [
            ("application.theme", "Theme", "option", ["dark", "light"]),
            ("application.auto_refresh_interval", "Auto-refresh Interval (ms)", "entry"),
            ("application.max_popups_per_rule", "Max Alerts per Rule", "entry"),
            ("ui.show_welcome_screen", "Show Welcome Screen", "switch"),
            ("ui.confirm_before_delete", "Confirm Before Delete", "switch"),
            ("ui.enable_tooltips", "Enable Tooltips", "switch"),
        ])

        self._create_section(settings_scroll, "YARA Settings", [
            ("yara.create_backups_on_delete", "Create Backups on Delete", "switch"),
            ("yara.create_backups_on_update", "Create Backups on Update", "switch"),
        ])

        self._create_section(settings_scroll, "Export Settings", [
            ("export.default_export_format", "Default Export Format", "option", ["json", "csv"]),
            ("export.include_metadata", "Include Metadata", "switch"),
            ("export.include_hashes", "Include File Hashes", "switch"),
        ])

        self._create_section(settings_scroll, "Advanced", [
            ("advanced.debug_mode", "Debug Mode", "switch"),
            ("advanced.log_file", "Log Filename", "entry"),
            ("advanced.max_log_size_mb", "Max Log Size (MB)", "entry"),
        ])

        self._create_section(settings_scroll, "Network Sharing", [
            ("network.analyst_name", "Analyst Name", "entry"),
            ("network.enable_network_case_folder", "Enable Network Case Folder", "switch"),
            ("network.network_case_folder_path", "Network Case Folder Path", "entry"),
            ("network.enable_network_yara_sync", "Enable Network YARA Sync", "switch"),
            ("network.network_yara_path", "Network YARA Path", "entry"),
        ])

        # Load current settings
        self.load_settings_to_ui()

        # Store reference in app for backward compatibility
        self.app.settings_widgets = self.settings_widgets

        return self.frame

    def _create_section(self, parent, section_name: str, settings_list: list):
        """Create a settings section with multiple settings"""
        section_frame = ctk.CTkFrame(
            parent, fg_color=self.colors["navy"], corner_radius=10
        )
        section_frame.pack(fill="x", pady=10, padx=10)

        header = ctk.CTkLabel(
            section_frame, text=section_name,
            font=Fonts.label_large,
            text_color="white"
        )
        header.pack(anchor="w", padx=20, pady=15)

        for setting_info in settings_list:
            key_path = setting_info[0]
            label_text = setting_info[1]
            widget_type = setting_info[2]
            options = setting_info[3] if len(setting_info) > 3 else None
            self._create_setting_item(section_frame, key_path, label_text, widget_type, options)

    def _create_setting_item(
            self, parent, key_path: str, label_text: str,
            widget_type: str, options: Optional[list] = None
    ):
        """Create a single setting item"""
        item_frame = ctk.CTkFrame(parent, fg_color="transparent")
        item_frame.pack(fill="x", padx=20, pady=5)

        label = ctk.CTkLabel(
            item_frame, text=label_text,
            font=Fonts.label_large,
            text_color="white",
            width=300,
            anchor="w"
        )
        label.pack(side="left", padx=10)

        widget = None
        if widget_type == "entry":
            widget = ctk.CTkEntry(item_frame, font=Fonts.label_large, width=300)
            widget.pack(side="right", padx=10, pady=5)
        elif widget_type == "switch":
            widget = ctk.CTkSwitch(item_frame, text="", font=Fonts.label_large)
            widget.pack(side="right", padx=10, pady=5)
        elif widget_type == "option" and options:
            widget = ctk.CTkOptionMenu(
                item_frame, values=options,
                font=Fonts.label_large, width=200
            )
            widget.pack(side="right", padx=10, pady=5)

        if widget:
            self.settings_widgets[key_path] = widget

    def load_settings_to_ui(self):
        """Load settings from manager into UI widgets"""
        for key_path, widget in self.settings_widgets.items():
            value = self.app.settings_manager.get(key_path)

            if isinstance(widget, ctk.CTkEntry):
                widget.delete(0, "end")
                widget.insert(0, str(value) if value is not None else "")
            elif isinstance(widget, ctk.CTkSwitch):
                if value:
                    widget.select()
                else:
                    widget.deselect()
            elif isinstance(widget, ctk.CTkOptionMenu):
                widget.set(str(value))

    def save_settings(self):
        """Save settings from UI to settings manager"""
        for key_path, widget in self.settings_widgets.items():
            if isinstance(widget, ctk.CTkEntry):
                value = widget.get()
                try:
                    if value.isdigit():
                        value = int(value)
                    elif value.replace('.', '', 1).isdigit():
                        value = float(value)
                except:
                    pass
                self.app.settings_manager.set(key_path, value)
            elif isinstance(widget, ctk.CTkSwitch):
                value = widget.get() == 1
                self.app.settings_manager.set(key_path, value)
            elif isinstance(widget, ctk.CTkOptionMenu):
                value = widget.get()
                self.app.settings_manager.set(key_path, value)

        if self.app.settings_manager.save_settings():
            self.apply_settings()
            messagebox.showinfo(
                "Success",
                "Settings saved and applied successfully.\n\n"
                "Note: API key changes will take effect for new operations."
            )
        else:
            messagebox.showerror("Error", "Failed to save settings")

    def apply_settings(self):
        """Apply settings to the running application"""
        self.app.auto_refresh_interval = self.app.settings_manager.get(
            "application.auto_refresh_interval", 2000
        )
        self.app.max_popups_per_rule = self.app.settings_manager.get(
            "application.max_popups_per_rule", 3
        )

        # Update API keys in case manager
        vt_api_key = self.app.settings_manager.get("api_keys.virustotal")
        threathq_user = self.app.settings_manager.get("api_keys.threathq_user")
        threathq_pass = self.app.settings_manager.get("api_keys.threathq_pass")

        if vt_api_key:
            self.app.case_manager.vt_api_key = vt_api_key
        if threathq_user:
            self.app.case_manager.threathq_user = threathq_user
        if threathq_pass:
            self.app.case_manager.threathq_pass = threathq_pass

        print("Settings applied successfully")

    def reset_settings(self):
        """Reset settings to defaults"""
        result = messagebox.askyesno(
            "Confirm Reset",
            "Are you sure you want to reset all settings to defaults?\n\n"
            "This action cannot be undone."
        )

        if not result:
            return

        if self.app.settings_manager.reset_to_defaults():
            self.load_settings_to_ui()
            self.apply_settings()
            messagebox.showinfo("Success", "Settings reset to defaults and applied")
        else:
            messagebox.showerror("Error", "Failed to reset settings")
