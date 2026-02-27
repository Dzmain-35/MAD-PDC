"""
Network Analysis view for MAD.
Placeholder view for upcoming network analysis features.
"""

import customtkinter as ctk
from views.base_view import BaseView
from typography import Fonts


class NetworkView(BaseView):
    """Placeholder view for Network Analysis functionality."""

    def __init__(self, parent, app, colors):
        super().__init__(parent, app, colors)
        self._build_ui()

    def _build_ui(self):
        """Build the placeholder Network Analysis UI."""
        # Center container
        center_frame = ctk.CTkFrame(self.frame, fg_color="transparent")
        center_frame.place(relx=0.5, rely=0.5, anchor="center")

        # Icon
        icon_label = ctk.CTkLabel(
            center_frame, text="🌐",
            font=ctk.CTkFont(size=64),
            text_color="white"
        )
        icon_label.pack(pady=(0, 20))

        # Title
        title_label = ctk.CTkLabel(
            center_frame, text="Network Analysis",
            font=Fonts.header_main,
            text_color="white"
        )
        title_label.pack(pady=(0, 10))

        # Subtitle
        subtitle_label = ctk.CTkLabel(
            center_frame, text="Coming Soon",
            font=Fonts.title_large,
            text_color="#9ca3af"
        )
        subtitle_label.pack(pady=(0, 20))

        # Description
        desc_label = ctk.CTkLabel(
            center_frame,
            text="Network traffic capture, DNS analysis, and connection monitoring\n"
                 "will be available in a future update.",
            font=Fonts.body,
            text_color="#6b7280",
            justify="center"
        )
        desc_label.pack(pady=(0, 10))

    def on_activate(self):
        """Called when view gains focus."""
        pass

    def on_deactivate(self):
        """Called when view loses focus."""
        pass
