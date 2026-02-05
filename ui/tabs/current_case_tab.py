"""
Current Case Tab
Tab for viewing and managing the current malware analysis case.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog
import os
import webbrowser
from typing import TYPE_CHECKING, Optional, Dict, Any

from typography import Fonts
from .base_tab import BaseTab

if TYPE_CHECKING:
    from ui.app import ForensicAnalysisGUI


class CurrentCaseTab(BaseTab):
    """Tab for viewing and managing the current case"""

    def __init__(self, app: 'ForensicAnalysisGUI', parent: ctk.CTkFrame):
        super().__init__(app, parent)
        self.case_status_label = None
        self.case_info_frame = None
        self.case_details_frame = None
        self.files_list_frame = None
        self.files_expand_indicator = None
        self.iocs_content_frame = None
        self.iocs_expand_indicator = None
        self.iocs_urls_list = None
        self.iocs_ips_list = None
        self.iocs_domains_list = None
        self.notes_textbox = None
        self.notes_expand_indicator = None

        # Visibility states
        self.files_section_visible = [True]
        self.iocs_section_visible = [True]
        self.notes_section_visible = [True]

    def _handle_add_files(self):
        """Handle adding files to the current case via file dialog"""
        if not self.app.current_case:
            messagebox.showwarning("No Case", "No active case. Please create a new case first.")
            return

        # Open file dialog
        files = filedialog.askopenfilenames(
            title="Select files to add to case",
            filetypes=[
                ("All files", "*.*"),
                ("Executables", "*.exe *.dll *.sys"),
                ("Scripts", "*.ps1 *.bat *.vbs *.js"),
                ("Documents", "*.doc *.docx *.xls *.xlsx *.pdf"),
                ("Archives", "*.zip *.rar *.7z")
            ]
        )

        if not files:
            return  # User cancelled

        files = list(files)

        # Show progress window and add files
        self.app.show_progress_window("Adding Files")

        def progress_callback(current, total, filename):
            self.app.update_progress(current, total, f"Processing: {filename}")

        self.app.handle_add_files(files, progress_callback)

    def create(self) -> ctk.CTkFrame:
        """Create the Current Case tab interface"""
        self.frame = ctk.CTkFrame(self.parent, fg_color=self.colors["dark_blue"])

        # Header with title and status
        header_frame = ctk.CTkFrame(self.frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=10, padx=20)

        title = ctk.CTkLabel(
            header_frame, text="Current Case",
            font=Fonts.header_section,
            text_color="white"
        )
        title.pack(side="left")

        self.case_status_label = ctk.CTkLabel(
            header_frame, text="",
            corner_radius=20,
            fg_color="#2D7A3E",
            width=100, height=30,
            text_color="white",
            font=Fonts.label
        )
        self.case_status_label.pack(side="right", padx=10)

        # Scrollable frame for content
        scroll_frame = ctk.CTkScrollableFrame(
            self.frame, corner_radius=10, fg_color=self.colors["navy"]
        )
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        # Case details card
        self.case_details_frame = ctk.CTkFrame(scroll_frame, corner_radius=10, fg_color="gray20")
        self.case_details_frame.pack(fill="x", pady=5)

        details_title = ctk.CTkLabel(
            self.case_details_frame, text="Case Details",
            font=Fonts.title_medium,
            text_color="white"
        )
        details_title.pack(pady=10, padx=15, anchor="w")

        self.case_info_frame = ctk.CTkFrame(
            self.case_details_frame, fg_color="transparent"
        )
        self.case_info_frame.pack(fill="x", padx=15, pady=(0, 10))

        # Files section
        files_header, self.files_list_frame, self.files_expand_indicator = \
            self._create_collapsible_section(
                scroll_frame, "Uploaded Files", "➕ Add Files",
                self._handle_add_files, self.files_section_visible
            )

        # IOCs section
        iocs_header, iocs_container, self.iocs_expand_indicator = \
            self._create_collapsible_section(
                scroll_frame, "Indicators of Compromise (IOCs)", "➕ Add IOC",
                self.app.handle_add_ioc, self.iocs_section_visible,
                create_content_frame=True
            )

        self.iocs_content_frame = ctk.CTkFrame(iocs_container, fg_color="transparent")
        self.iocs_content_frame.pack(fill="both", expand=True, padx=15, pady=15)
        self._create_ioc_lists()

        # Notes section
        notes_header, notes_container, self.notes_expand_indicator = \
            self._create_collapsible_section(
                scroll_frame, "Case Notes", "💾 Save Notes",
                self.app.handle_save_notes, self.notes_section_visible,
                create_content_frame=True, expand=True
            )

        # Notes text widget
        self.notes_textbox = tk.Text(
            notes_container,
            wrap="word",
            bg="#1a1a1a",
            fg="#ffffff",
            font=Fonts.text_input(),
            relief="flat",
            padx=15,
            pady=15,
            height=8
        )
        self.notes_textbox.pack(fill="both", expand=True, padx=2, pady=2)

        # Setup toggle bindings
        self._setup_toggle_bindings(
            files_header, self.files_expand_indicator, self.files_list_frame,
            self.files_section_visible, iocs_header, "➕ Add Files"
        )

        self._setup_toggle_bindings(
            iocs_header, self.iocs_expand_indicator, iocs_container,
            self.iocs_section_visible, notes_header, "➕ Add IOC"
        )

        self._setup_toggle_bindings(
            notes_header, self.notes_expand_indicator, notes_container,
            self.notes_section_visible, None, "💾 Save Notes"
        )

        # Store references in app for backward compatibility
        self.app.case_status_label = self.case_status_label
        self.app.case_info_frame = self.case_info_frame
        self.app.case_details_frame = self.case_details_frame
        self.app.files_list_frame = self.files_list_frame
        self.app.files_expand_indicator = self.files_expand_indicator
        self.app.iocs_content_frame = self.iocs_content_frame
        self.app.iocs_expand_indicator = self.iocs_expand_indicator
        self.app.iocs_urls_list = self.iocs_urls_list
        self.app.iocs_ips_list = self.iocs_ips_list
        self.app.iocs_domains_list = self.iocs_domains_list
        self.app.notes_textbox = self.notes_textbox
        self.app.notes_expand_indicator = self.notes_expand_indicator
        self.app.files_section_visible = self.files_section_visible
        self.app.iocs_section_visible = self.iocs_section_visible
        self.app.notes_section_visible = self.notes_section_visible

        return self.frame

    def _create_collapsible_section(
            self, parent, title_text: str, button_text: str,
            button_command, visibility_state: list,
            create_content_frame: bool = False, expand: bool = False
    ):
        """Create a collapsible section with header and content area"""
        # Header
        header = ctk.CTkFrame(parent, corner_radius=10, fg_color="gray20", cursor="hand2")
        header.pack(fill="x", pady=(10, 5))

        header_inner = ctk.CTkFrame(header, fg_color="transparent", cursor="hand2")
        header_inner.pack(fill="x", padx=15, pady=10)

        # Expand indicator
        expand_indicator = ctk.CTkLabel(
            header_inner, text="▼",
            font=Fonts.body_large,
            text_color="gray60",
            cursor="hand2"
        )
        expand_indicator.pack(side="left", padx=(0, 10))

        # Title
        title = ctk.CTkLabel(
            header_inner, text=title_text,
            font=Fonts.title_medium,
            text_color="white",
            cursor="hand2"
        )
        title.pack(side="left")

        # Action button
        btn = ctk.CTkButton(
            header_inner, text=button_text,
            command=button_command,
            height=30, width=100,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            font=Fonts.label
        )
        btn.pack(side="right")

        # Content container
        if create_content_frame:
            content = ctk.CTkFrame(parent, corner_radius=10, fg_color="gray20")
            if expand:
                content.pack(fill="both", expand=True, pady=(0, 10))
            else:
                content.pack(fill="x", pady=(0, 10))
        else:
            content = ctk.CTkFrame(parent, corner_radius=10, fg_color="transparent")
            content.pack(fill="x", pady=(0, 10))

        return header, content, expand_indicator

    def _create_ioc_lists(self):
        """Create IOC list components"""
        # URLs
        urls_frame = ctk.CTkFrame(self.iocs_content_frame, fg_color="#1a1a1a", corner_radius=5)
        urls_frame.pack(fill="x", pady=(0, 10))

        urls_label = ctk.CTkLabel(
            urls_frame, text="URLs:",
            font=Fonts.body_bold,
            text_color="white", anchor="w"
        )
        urls_label.pack(anchor="w", padx=10, pady=(10, 5))

        self.iocs_urls_list = ctk.CTkTextbox(
            urls_frame, height=80,
            fg_color="#0d1520", corner_radius=5
        )
        self.iocs_urls_list.pack(fill="x", padx=10, pady=(0, 10))

        # IPs
        ips_frame = ctk.CTkFrame(self.iocs_content_frame, fg_color="#1a1a1a", corner_radius=5)
        ips_frame.pack(fill="x", pady=(0, 10))

        ips_label = ctk.CTkLabel(
            ips_frame, text="IP Addresses:",
            font=Fonts.body_bold,
            text_color="white", anchor="w"
        )
        ips_label.pack(anchor="w", padx=10, pady=(10, 5))

        self.iocs_ips_list = ctk.CTkTextbox(
            ips_frame, height=80,
            fg_color="#0d1520", corner_radius=5
        )
        self.iocs_ips_list.pack(fill="x", padx=10, pady=(0, 10))

        # Domains
        domains_frame = ctk.CTkFrame(self.iocs_content_frame, fg_color="#1a1a1a", corner_radius=5)
        domains_frame.pack(fill="x", pady=(0, 10))

        domains_label = ctk.CTkLabel(
            domains_frame, text="Domains:",
            font=Fonts.body_bold,
            text_color="white", anchor="w"
        )
        domains_label.pack(anchor="w", padx=10, pady=(10, 5))

        self.iocs_domains_list = ctk.CTkTextbox(
            domains_frame, height=80,
            fg_color="#0d1520", corner_radius=5
        )
        self.iocs_domains_list.pack(fill="x", padx=10, pady=(0, 10))

    def _setup_toggle_bindings(
            self, header, indicator, content,
            visibility_state: list, next_header, button_text: str
    ):
        """Setup toggle bindings for a collapsible section"""
        def toggle(event=None):
            # Prevent toggle when clicking the button
            if event and hasattr(event.widget, 'cget'):
                try:
                    if event.widget.cget('text') == button_text:
                        return
                except:
                    pass

            if visibility_state[0]:
                content.pack_forget()
                indicator.configure(text="▶")
                visibility_state[0] = False
            else:
                if next_header:
                    content.pack(fill="x", pady=(0, 10), before=next_header)
                else:
                    content.pack(fill="both", expand=True, pady=(0, 10))
                indicator.configure(text="▼")
                visibility_state[0] = True

        # Bind to all elements
        for widget in [header] + list(header.winfo_children()):
            widget.bind("<Button-1>", toggle)
        indicator.bind("<Button-1>", toggle)

    def on_show(self):
        """Called when tab is shown - refresh the display"""
        self.refresh()

    def refresh(self):
        """Refresh the tab content with current case data"""
        current_case = self.app.current_case

        if not current_case:
            self.case_status_label.configure(text="No Case")
            # Clear case info
            for widget in self.case_info_frame.winfo_children():
                widget.destroy()
            no_case_label = ctk.CTkLabel(
                self.case_info_frame,
                text="No case loaded. Create a new case to get started.",
                font=Fonts.body,
                text_color="gray60"
            )
            no_case_label.pack(pady=20)
            return

        # Update status
        self.case_status_label.configure(text="Active")

        # Update case info
        for widget in self.case_info_frame.winfo_children():
            widget.destroy()

        info_items = [
            ("Case Name:", current_case.get("name", "N/A")),
            ("Analyst:", current_case.get("analyst_name", "N/A")),
            ("Created:", current_case.get("created", "N/A")[:10] if current_case.get("created") else "N/A"),
            ("Files:", str(len(current_case.get("files", [])))),
            ("Threats:", str(current_case.get("total_threats", 0))),
        ]

        for label_text, value in info_items:
            row = ctk.CTkFrame(self.case_info_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)

            label = ctk.CTkLabel(row, text=label_text, font=Fonts.body_bold, text_color="gray60", width=100, anchor="w")
            label.pack(side="left")

            value_label = ctk.CTkLabel(row, text=value, font=Fonts.body, text_color="white", anchor="w")
            value_label.pack(side="left", padx=10)

        # Refresh IOCs display
        self.app.case_handlers.refresh_iocs_display()

        # Load notes if available
        notes = current_case.get("notes", "")
        self.notes_textbox.delete("1.0", "end")
        if notes:
            self.notes_textbox.insert("1.0", notes)
