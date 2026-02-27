"""
Base view class for all MAD views.
Provides common interface and shared utilities.
"""

import customtkinter as ctk


class BaseView:
    """Base class for all MAD view modules.

    Each view owns a frame, its widgets, and event handlers.
    The main app shell coordinates between views via the EventBus.
    """

    def __init__(self, parent, app, colors):
        """
        Args:
            parent: Parent widget (content_area frame)
            app: Reference to the main ForensicAnalysisGUI instance
            colors: Color scheme dict
        """
        self.parent = parent
        self.app = app
        self.colors = colors
        self.frame = ctk.CTkFrame(parent, fg_color=colors["dark_blue"])

    @property
    def root(self):
        """Convenience accessor for the Tk root window."""
        return self.app.root

    @property
    def settings_manager(self):
        return self.app.settings_manager

    @property
    def case_manager(self):
        return self.app.case_manager

    @property
    def is_large_screen(self):
        return self.app._is_large_screen

    def show(self):
        """Make this view visible."""
        self.frame.pack(fill="both", expand=True)

    def hide(self):
        """Hide this view."""
        self.frame.pack_forget()

    def on_activate(self):
        """Called when view gains focus. Override to refresh data."""
        pass

    def on_deactivate(self):
        """Called when view loses focus. Override to pause updates."""
        pass

    def destroy(self):
        """Clean up resources. Override for cleanup logic."""
        self.frame.destroy()
