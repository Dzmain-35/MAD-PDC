"""
Settings View for MAD - Application configuration management.
Extracted from MAD.py create_settings_tab() and related methods.
"""

import customtkinter as ctk
from tkinter import messagebox
from typography import Fonts
from views.base_view import BaseView


class SettingsView(BaseView):
    """Application settings management view."""

    def __init__(self, parent, app, colors):
        super().__init__(parent, app, colors)
        self.settings_widgets = {}
        self._build()

    def _build(self):
        """Build the settings UI."""
        frame = self.frame

        # Header
        header_frame = ctk.CTkFrame(frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=20)

        title = ctk.CTkLabel(header_frame, text="Application Settings",
                             font=Fonts.header_subsection,
                             text_color="white")
        title.pack(side="left")

        # Action buttons
        btn_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        btn_frame.pack(side="right")

        _settings_font = Fonts.label_large if self.is_large_screen else Fonts.label
        btn_save = ctk.CTkButton(btn_frame, text="Save Settings",
                                 command=self.save_settings,
                                 fg_color=self.colors["red"],
                                 hover_color=self.colors["red_dark"],
                                 font=_settings_font)
        btn_save.pack(side="left", padx=5)

        btn_reset = ctk.CTkButton(btn_frame, text="Reset to Defaults",
                                  command=self.reset_settings,
                                  fg_color=self.colors["navy"],
                                  hover_color=self.colors["dark_blue"],
                                  font=_settings_font)
        btn_reset.pack(side="left", padx=5)

        # Scrollable settings container
        settings_scroll = ctk.CTkScrollableFrame(frame, fg_color="transparent")
        settings_scroll.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # UI Settings
        self._create_section(settings_scroll, "User Interface", [
            ("application.theme", "Theme", "option", ["dark", "light"]),
            ("application.auto_refresh_interval", "Auto-refresh Interval (ms)", "entry"),
            ("application.max_popups_per_rule", "Max Alerts per Rule", "entry"),
            ("ui.show_welcome_screen", "Show Welcome Screen", "switch"),
            ("ui.confirm_before_delete", "Confirm Before Delete", "switch"),
            ("ui.enable_tooltips", "Enable Tooltips", "switch"),
        ])

        # YARA Settings
        self._create_section(settings_scroll, "YARA Settings", [
            ("yara.enable_rule_creation", "Enable YARA Rule Creation", "switch"),
            ("yara.create_backups_on_delete", "Create Backups on Delete", "switch"),
            ("yara.create_backups_on_update", "Create Backups on Update", "switch"),
        ])

        # Network Settings
        self._create_section(settings_scroll, "Network Sharing", [
            ("network.analyst_name", "Analyst Name", "entry"),
            ("network.enable_network_case_folder", "Enable Network Case Folder", "switch"),
            ("network.network_case_folder_path", "Network Case Folder Path", "entry"),
            ("network.enable_network_yara_sync", "Enable Network YARA Sync", "switch"),
            ("network.network_yara_path", "Network YARA Path", "entry"),
        ])

        # Load current settings
        self._load_settings_to_ui()

    def _create_section(self, parent, section_name, settings_list):
        """Create a settings section with multiple settings."""
        section_frame = ctk.CTkFrame(parent, fg_color=self.colors["navy"],
                                     corner_radius=10)
        section_frame.pack(fill="x", pady=10, padx=10)

        header = ctk.CTkLabel(section_frame, text=section_name,
                              font=Fonts.label_large,
                              text_color="white")
        header.pack(anchor="w", padx=20, pady=15)

        for setting_info in settings_list:
            key_path = setting_info[0]
            label_text = setting_info[1]
            widget_type = setting_info[2]
            options = setting_info[3] if len(setting_info) > 3 else None
            self._create_setting_item(section_frame, key_path, label_text, widget_type, options)

    def _create_setting_item(self, parent, key_path, label_text, widget_type, options=None):
        """Create a single setting item."""
        item_frame = ctk.CTkFrame(parent, fg_color="transparent")
        item_frame.pack(fill="x", padx=20, pady=5)

        label_w = 320 if self.is_large_screen else 220
        entry_w = 350 if self.is_large_screen else 230

        label = ctk.CTkLabel(item_frame, text=label_text,
                             font=Fonts.label_large if self.is_large_screen else Fonts.label,
                             text_color="white",
                             width=label_w,
                             anchor="w")
        label.pack(side="left", padx=10)

        if widget_type == "entry":
            widget = ctk.CTkEntry(item_frame, font=Fonts.label_large if self.is_large_screen else Fonts.label, width=entry_w)
            widget.pack(side="right", padx=10, pady=5)
        elif widget_type == "switch":
            widget = ctk.CTkSwitch(item_frame, text="", font=Fonts.label_large if self.is_large_screen else Fonts.label)
            widget.pack(side="right", padx=10, pady=5)
        elif widget_type == "option" and options:
            widget = ctk.CTkOptionMenu(item_frame, values=options,
                                       font=Fonts.label_large if self.is_large_screen else Fonts.label, width=entry_w - 100)
            widget.pack(side="right", padx=10, pady=5)
        else:
            return

        self.settings_widgets[key_path] = widget

    def _load_settings_to_ui(self):
        """Load settings from manager into UI widgets."""
        for key_path, widget in self.settings_widgets.items():
            value = self.settings_manager.get(key_path)

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
        """Save settings from UI to settings manager."""
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
                self.settings_manager.set(key_path, value)
            elif isinstance(widget, ctk.CTkSwitch):
                value = widget.get() == 1
                self.settings_manager.set(key_path, value)
            elif isinstance(widget, ctk.CTkOptionMenu):
                value = widget.get()
                self.settings_manager.set(key_path, value)

        if self.settings_manager.save_settings():
            self._apply_settings()
            messagebox.showinfo("Success", "Settings saved and applied successfully.\n\nNote: API key changes will take effect for new operations.")
        else:
            messagebox.showerror("Error", "Failed to save settings")

    def _apply_settings(self):
        """Apply settings to the running application."""
        self.app.auto_refresh_interval = self.settings_manager.get("application.auto_refresh_interval", 2000)
        self.app.max_popups_per_rule = self.settings_manager.get("application.max_popups_per_rule", 3)

        # Update API keys in case manager
        vt_api_key = self.settings_manager.get("api_keys.virustotal")
        threathq_user = self.settings_manager.get("api_keys.threathq_user")
        threathq_pass = self.settings_manager.get("api_keys.threathq_pass")

        if vt_api_key:
            self.case_manager.vt_api_key = vt_api_key
        if threathq_user:
            self.case_manager.threathq_user = threathq_user
        if threathq_pass:
            self.case_manager.threathq_pass = threathq_pass

        # Apply YARA rule creation setting
        yara_creation_enabled = self.settings_manager.get("yara.enable_rule_creation", True)
        yara_view = self.app.views.get("yara_rules")
        if yara_view:
            yara_view.apply_creation_setting(yara_creation_enabled)

        print("Settings applied successfully")

    def reset_settings(self):
        """Reset settings to defaults."""
        result = messagebox.askyesno(
            "Confirm Reset",
            "Are you sure you want to reset all settings to defaults?\n\nThis action cannot be undone."
        )

        if not result:
            return

        if self.settings_manager.reset_to_defaults():
            self._load_settings_to_ui()
            self._apply_settings()
            messagebox.showinfo("Success", "Settings reset to defaults and applied")
        else:
            messagebox.showerror("Error", "Failed to reset settings")
