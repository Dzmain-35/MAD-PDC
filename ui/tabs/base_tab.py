"""
Base Tab Class
Abstract base class for all application tabs.
"""

import customtkinter as ctk
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ui.app import ForensicAnalysisGUI


class BaseTab(ABC):
    """
    Abstract base class for application tabs.

    Each tab should inherit from this class and implement the create() method.
    """

    def __init__(self, app: 'ForensicAnalysisGUI', parent: ctk.CTkFrame):
        """
        Initialize the tab.

        Args:
            app: Reference to the main application instance
            parent: Parent frame (content area) where the tab will be placed
        """
        self.app = app
        self.parent = parent
        self.colors = app.colors
        self.frame = None

    @abstractmethod
    def create(self) -> ctk.CTkFrame:
        """
        Create and return the tab's frame.

        Returns:
            The main frame of the tab
        """
        pass

    def show(self):
        """Show this tab"""
        if self.frame:
            self.frame.pack(fill="both", expand=True)

    def hide(self):
        """Hide this tab"""
        if self.frame:
            self.frame.pack_forget()

    def on_show(self):
        """Called when the tab is shown. Override for custom behavior."""
        pass

    def on_hide(self):
        """Called when the tab is hidden. Override for custom behavior."""
        pass

    def refresh(self):
        """Refresh the tab content. Override if needed."""
        pass
