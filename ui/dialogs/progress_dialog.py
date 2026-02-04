"""
Progress Dialog
Dialog for displaying scan progress with cancel functionality.
"""

import customtkinter as ctk
from typing import TYPE_CHECKING, Optional, Callable

from typography import Fonts
from ui.theme import Colors

if TYPE_CHECKING:
    from ui.app import ForensicAnalysisGUI


class ProgressDialog:
    """Progress dialog for file scanning operations"""

    def __init__(
            self, app: 'ForensicAnalysisGUI',
            total_items: int,
            title: str = "Scanning Files",
            subtitle: str = "YARA & Threat Intelligence Analysis"
    ):
        self.app = app
        self.total_items = total_items
        self.window: Optional[ctk.CTkToplevel] = None
        self.progress_bar: Optional[ctk.CTkProgressBar] = None
        self.progress_label: Optional[ctk.CTkLabel] = None
        self.current_file_label: Optional[ctk.CTkLabel] = None
        self.cancel_callback: Optional[Callable] = None
        self._cancelled = False

        self._create_window(title, subtitle)

    def _create_window(self, title: str, subtitle: str):
        """Create the progress dialog window"""
        self.window = ctk.CTkToplevel(self.app.root)
        self.window.title(title)
        self.window.geometry("550x250")
        self.window.transient(self.app.root)
        self.window.grab_set()
        self.window.resizable(False, False)

        # Center the window
        self.window.update_idletasks()
        x = (self.window.winfo_screenwidth() // 2) - (550 // 2)
        y = (self.window.winfo_screenheight() // 2) - (250 // 2)
        self.window.geometry(f"550x250+{x}+{y}")

        # Main container
        container = ctk.CTkFrame(self.window, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=30, pady=30)

        # Title
        title_label = ctk.CTkLabel(
            container,
            text=title,
            font=Fonts.title_large
        )
        title_label.pack(pady=(0, 5))

        subtitle_label = ctk.CTkLabel(
            container,
            text=subtitle,
            font=Fonts.body,
            text_color="gray60"
        )
        subtitle_label.pack(pady=(0, 20))

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(container, width=450, height=20)
        self.progress_bar.pack(pady=10)
        self.progress_bar.set(0)

        # Status label
        self.progress_label = ctk.CTkLabel(
            container,
            text=f"Processing 0 of {self.total_items} files...",
            font=Fonts.body_large_bold
        )
        self.progress_label.pack(pady=10)

        # Current file label
        self.current_file_label = ctk.CTkLabel(
            container,
            text="Initializing...",
            font=Fonts.helper,
            text_color="gray60"
        )
        self.current_file_label.pack(pady=5)

        # Cancel button
        cancel_btn = ctk.CTkButton(
            container,
            text="Cancel Scan",
            command=self._on_cancel,
            fg_color=Colors.RED,
            hover_color=Colors.RED_DARK,
            width=120,
            height=35
        )
        cancel_btn.pack(pady=15)

    def update(self, current: int, current_file: str):
        """Update progress bar and labels"""
        if self.window and self.window.winfo_exists():
            progress = current / self.total_items
            self.progress_bar.set(progress)
            self.progress_label.configure(
                text=f"Processing {current} of {self.total_items} files..."
            )
            self.current_file_label.configure(text=current_file)

    def _on_cancel(self):
        """Handle cancel button click"""
        self._cancelled = True
        if self.cancel_callback:
            self.cancel_callback()
        self.close()

    def set_cancel_callback(self, callback: Callable):
        """Set callback for cancel action"""
        self.cancel_callback = callback

    @property
    def cancelled(self) -> bool:
        """Check if dialog was cancelled"""
        return self._cancelled

    def close(self):
        """Close the progress dialog"""
        if self.window and self.window.winfo_exists():
            self.window.destroy()
            self.window = None

    def is_open(self) -> bool:
        """Check if dialog is still open"""
        return self.window is not None and self.window.winfo_exists()
