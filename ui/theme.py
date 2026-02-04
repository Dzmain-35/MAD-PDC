"""
MAD Theme Configuration
Centralized color scheme and styling constants for the application.
"""

import customtkinter as ctk


class Colors:
    """Application color palette"""

    # Primary colors
    DARK_BLUE = "#1a2332"
    NAVY = "#0d1520"
    RED = "#dc2626"
    RED_DARK = "#991b1b"

    # UI element colors
    SIDEBAR_BG = "#991b1b"
    CARD_BG = "gray20"
    INPUT_BG = "#1a1a1a"

    # Status colors
    SUCCESS = "#10b981"
    WARNING = "#f59e0b"
    ERROR = "#ef4444"
    INFO = "#3b82f6"

    # Process states
    THREAT_BG = "#5c1c1c"
    NEW_PROCESS_BG = "#8B7500"
    BENIGN_BG = "#1a4d2e"
    SUSPENDED_BG = "#3a3a3a"
    SUSPENDED_FG = "#808080"
    SYSTEM_FG = "#888888"

    # YARA badge
    YARA_BADGE_FG = "#fbbf24"
    YARA_BADGE_BG = "#78350f"

    @classmethod
    def as_dict(cls):
        """Return colors as dictionary for backward compatibility"""
        return {
            "dark_blue": cls.DARK_BLUE,
            "navy": cls.NAVY,
            "red": cls.RED,
            "red_dark": cls.RED_DARK,
            "sidebar_bg": cls.SIDEBAR_BG,
        }


class Theme:
    """Application theme configuration"""

    # Theme settings
    APPEARANCE_MODE = "dark"
    COLOR_THEME = "blue"

    # Window settings
    DEFAULT_GEOMETRY = "1200x800"
    TITLE = "MAD - Malware Analysis Dashboard"

    # Treeview style configuration
    TREEVIEW_BG = "#1a1a1a"
    TREEVIEW_FG = "white"
    TREEVIEW_FIELD_BG = "#1a1a1a"
    TREEVIEW_SELECTED_BG = "#dc2626"
    TREEVIEW_HEADING_BG = "#0d1520"
    TREEVIEW_HEADING_FG = "white"
    TREEVIEW_HEADING_ACTIVE_BG = "#1a2332"

    # Menu style
    MENU_BG = "#1a1a1a"
    MENU_FG = "white"
    MENU_ACTIVE_BG = "#dc2626"
    MENU_ACTIVE_FG = "white"

    @classmethod
    def apply(cls):
        """Apply theme settings to customtkinter"""
        ctk.set_appearance_mode(cls.APPEARANCE_MODE)
        ctk.set_default_color_theme(cls.COLOR_THEME)

    @classmethod
    def get_treeview_style_config(cls, style_name="Custom.Treeview"):
        """Get treeview style configuration dictionary"""
        return {
            "style_name": style_name,
            "background": cls.TREEVIEW_BG,
            "foreground": cls.TREEVIEW_FG,
            "fieldbackground": cls.TREEVIEW_FIELD_BG,
            "selected_bg": cls.TREEVIEW_SELECTED_BG,
            "heading_bg": cls.TREEVIEW_HEADING_BG,
            "heading_fg": cls.TREEVIEW_HEADING_FG,
            "heading_active_bg": cls.TREEVIEW_HEADING_ACTIVE_BG,
        }

    @classmethod
    def get_menu_config(cls):
        """Get menu style configuration dictionary"""
        return {
            "bg": cls.MENU_BG,
            "fg": cls.MENU_FG,
            "activebackground": cls.MENU_ACTIVE_BG,
            "activeforeground": cls.MENU_ACTIVE_FG,
            "borderwidth": 0,
            "relief": "flat",
        }
