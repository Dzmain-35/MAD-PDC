"""
Current Case View for MAD - Displays and manages the active case.
Extracted from MAD.py create_current_case_tab() and related methods.
"""

import os
import platform
import subprocess
import threading
import webbrowser
import shutil
from datetime import datetime

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog
from PIL import Image

from typography import Fonts
from analysis_modules.file_viewer_executor import get_viewer_executor
from views.base_view import BaseView


class CurrentCaseView(BaseView):
    """Current case display with files, IOCs, notes, and screenshots."""

    def __init__(self, parent, app, colors):
        super().__init__(parent, app, colors)

        # View-local widget references
        self.case_status_label = None
        self.case_details_frame = None
        self.case_info_frame = None
        self.files_list_frame = None
        self.files_expand_indicator = None
        self.iocs_header = None
        self.iocs_expand_indicator = None
        self.iocs_container = None
        self.iocs_content_frame = None
        self.iocs_urls_frame = None
        self.iocs_urls_list = None
        self.iocs_ips_frame = None
        self.iocs_ips_list = None
        self.iocs_domains_frame = None
        self.iocs_domains_list = None
        self.notes_header = None
        self.notes_expand_indicator = None
        self.notes_container = None
        self.notes_textbox = None
        self.screenshots_header = None
        self.screenshots_expand_indicator = None
        self.screenshots_container = None
        self.screenshots_display_frame = None
        self.screenshots_placeholder = None
        self.screenshot_images = []

        # Section visibility states (lists for closure mutability)
        self.files_section_visible = [False]
        self.iocs_section_visible = [False]
        self.notes_section_visible = [False]
        self.screenshots_section_visible = [False]

        self._build()

    # ------------------------------------------------------------------
    # Properties for convenient access to app-level state
    # ------------------------------------------------------------------

    @property
    def current_case(self):
        return self.app.current_case

    @current_case.setter
    def current_case(self, value):
        self.app.current_case = value

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build(self):
        """Build the Current Case tab UI (replaces create_current_case_tab)."""
        frame = self.frame

        # Header with title and status
        header_frame = ctk.CTkFrame(frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=10, padx=20)

        title = ctk.CTkLabel(header_frame, text="Current Case",
                              font=Fonts.header_section,
                              text_color="white")
        title.pack(side="left")

        self.case_status_label = ctk.CTkLabel(header_frame, text="",
                                              corner_radius=20,
                                              fg_color="#2D7A3E",
                                              width=100, height=30,
                                              text_color="white",
                                              font=Fonts.label)
        self.case_status_label.pack(side="right", padx=10)

        # Scrollable frame for content
        scroll_frame = ctk.CTkScrollableFrame(frame, corner_radius=10,
                                              fg_color=self.colors["navy"])
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        # Case details card - COMPACT VERSION
        self.case_details_frame = ctk.CTkFrame(scroll_frame, corner_radius=10,
                                               fg_color="gray20")
        self.case_details_frame.pack(fill="x", pady=5)

        details_title = ctk.CTkLabel(self.case_details_frame, text="Case Details",
                                     font=Fonts.title_medium,
                                     text_color="white")
        details_title.pack(pady=10, padx=15, anchor="w")

        self.case_info_frame = ctk.CTkFrame(self.case_details_frame,
                                            fg_color="transparent")
        self.case_info_frame.pack(fill="x", padx=15, pady=(0, 10))

        # ---- Files section header (clickable) ----
        files_header = ctk.CTkFrame(scroll_frame, corner_radius=10,
                                    fg_color="gray20", cursor="hand2")
        files_header.pack(fill="x", pady=(10, 5))

        files_header_inner = ctk.CTkFrame(files_header, fg_color="transparent",
                                          cursor="hand2")
        files_header_inner.pack(fill="x", padx=15, pady=10)

        self.files_expand_indicator = ctk.CTkLabel(
            files_header_inner, text="\u25b6",
            font=Fonts.body_large, text_color="gray60", cursor="hand2")
        self.files_expand_indicator.pack(side="left", padx=(0, 10))

        files_title = ctk.CTkLabel(files_header_inner, text="Uploaded Files",
                                   font=Fonts.title_medium, text_color="white",
                                   cursor="hand2")
        files_title.pack(side="left")

        btn_add_files = ctk.CTkButton(
            files_header_inner, text="\u2795 Add Files",
            command=self.handle_add_files,
            height=30, width=100,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            font=Fonts.label)
        btn_add_files.pack(side="right")

        # Files list container (collapsible) - starts hidden
        self.files_list_frame = ctk.CTkFrame(scroll_frame, corner_radius=10,
                                             fg_color="transparent")
        # Don't pack initially - will be shown when files are added

        # ---- IOCs section header (clickable) ----
        self.iocs_header = ctk.CTkFrame(scroll_frame, corner_radius=10,
                                        fg_color="gray20", cursor="hand2")
        self.iocs_header.pack(fill="x", pady=(10, 5))

        iocs_header_inner = ctk.CTkFrame(self.iocs_header, fg_color="transparent",
                                         cursor="hand2")
        iocs_header_inner.pack(fill="x", padx=15, pady=10)

        self.iocs_expand_indicator = ctk.CTkLabel(
            iocs_header_inner, text="\u25b6",
            font=Fonts.body_large, text_color="gray60", cursor="hand2")
        self.iocs_expand_indicator.pack(side="left", padx=(0, 10))

        iocs_title = ctk.CTkLabel(iocs_header_inner,
                                  text="Indicators of Compromise (IOCs)",
                                  font=Fonts.title_medium, text_color="white",
                                  cursor="hand2")
        iocs_title.pack(side="left")

        btn_add_ioc = ctk.CTkButton(
            iocs_header_inner, text="\u2795 Add IOC",
            command=self.handle_add_ioc,
            height=30, width=100,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            font=Fonts.label)
        btn_add_ioc.pack(side="right")

        # IOCs container (collapsible) - starts hidden
        self.iocs_container = ctk.CTkFrame(scroll_frame, corner_radius=10,
                                           fg_color="gray20")
        # Don't pack initially

        self.iocs_content_frame = ctk.CTkFrame(self.iocs_container,
                                               fg_color="transparent")
        self.iocs_content_frame.pack(fill="both", expand=True, padx=15, pady=15)

        # ---- Notes section header (clickable) ----
        self.notes_header = ctk.CTkFrame(scroll_frame, corner_radius=10,
                                         fg_color="gray20", cursor="hand2")
        self.notes_header.pack(fill="x", pady=(10, 5))

        notes_header_inner = ctk.CTkFrame(self.notes_header, fg_color="transparent",
                                          cursor="hand2")
        notes_header_inner.pack(fill="x", padx=15, pady=10)

        self.notes_expand_indicator = ctk.CTkLabel(
            notes_header_inner, text="\u25b6",
            font=Fonts.body_large, text_color="gray60", cursor="hand2")
        self.notes_expand_indicator.pack(side="left", padx=(0, 10))

        notes_title = ctk.CTkLabel(notes_header_inner, text="Case Notes",
                                   font=Fonts.title_medium, text_color="white",
                                   cursor="hand2")
        notes_title.pack(side="left")

        btn_save_notes = ctk.CTkButton(
            notes_header_inner, text="\U0001f4be Save Notes",
            command=self.handle_save_notes,
            height=30, width=100,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            font=Fonts.label)
        btn_save_notes.pack(side="right")

        # Notes text area (collapsible) - starts hidden
        self.notes_container = ctk.CTkFrame(scroll_frame, corner_radius=10,
                                            fg_color="gray20")
        # Don't pack initially

        # ---- Screenshots section header (clickable) ----
        self.screenshots_header = ctk.CTkFrame(scroll_frame, corner_radius=10,
                                               fg_color="gray20", cursor="hand2")
        self.screenshots_header.pack(fill="x", pady=(10, 5))

        screenshots_header_inner = ctk.CTkFrame(self.screenshots_header,
                                                fg_color="transparent",
                                                cursor="hand2")
        screenshots_header_inner.pack(fill="x", padx=15, pady=10)

        self.screenshots_expand_indicator = ctk.CTkLabel(
            screenshots_header_inner, text="\u25b6",
            font=Fonts.body_large, text_color="gray60", cursor="hand2")
        self.screenshots_expand_indicator.pack(side="left", padx=(0, 10))

        screenshots_title = ctk.CTkLabel(screenshots_header_inner,
                                         text="Screenshots",
                                         font=Fonts.title_medium,
                                         text_color="white", cursor="hand2")
        screenshots_title.pack(side="left")

        btn_attach_screenshot = ctk.CTkButton(
            screenshots_header_inner,
            text="\U0001f4cb Paste from Clipboard",
            command=self.attach_screenshot_from_clipboard,
            height=30, width=160,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            font=Fonts.label)
        btn_attach_screenshot.pack(side="right")

        # Screenshots container (collapsible) - starts hidden
        self.screenshots_container = ctk.CTkFrame(scroll_frame, corner_radius=10,
                                                  fg_color="gray20")
        # Don't pack initially

        # Screenshots display frame (scrollable)
        self.screenshots_display_frame = ctk.CTkScrollableFrame(
            self.screenshots_container, fg_color="transparent", height=200)
        self.screenshots_display_frame.pack(fill="x", padx=10, pady=10)

        # Placeholder text when no screenshots
        self.screenshots_placeholder = ctk.CTkLabel(
            self.screenshots_display_frame,
            text="No screenshots attached. Use 'Paste from Clipboard' to add screenshots.",
            font=Fonts.body, text_color="gray")
        self.screenshots_placeholder.pack(pady=20)

        # ---- IOC sub-widgets ----
        self.iocs_urls_frame = ctk.CTkFrame(self.iocs_content_frame,
                                            fg_color="#1a1a1a", corner_radius=5)
        self.iocs_urls_frame.pack(fill="x", pady=(0, 10))

        urls_label = ctk.CTkLabel(self.iocs_urls_frame, text="URLs:",
                                  font=Fonts.body_bold,
                                  text_color="white", anchor="w")
        urls_label.pack(anchor="w", padx=10, pady=(10, 5))

        self.iocs_urls_list = ctk.CTkTextbox(self.iocs_urls_frame, height=80,
                                             fg_color="#0d1520", corner_radius=5)
        self.iocs_urls_list.pack(fill="x", padx=10, pady=(0, 10))

        self.iocs_ips_frame = ctk.CTkFrame(self.iocs_content_frame,
                                           fg_color="#1a1a1a", corner_radius=5)
        self.iocs_ips_frame.pack(fill="x", pady=(0, 10))

        ips_label = ctk.CTkLabel(self.iocs_ips_frame, text="IP Addresses:",
                                 font=Fonts.body_bold,
                                 text_color="white", anchor="w")
        ips_label.pack(anchor="w", padx=10, pady=(10, 5))

        self.iocs_ips_list = ctk.CTkTextbox(self.iocs_ips_frame, height=80,
                                            fg_color="#0d1520", corner_radius=5)
        self.iocs_ips_list.pack(fill="x", padx=10, pady=(0, 10))

        self.iocs_domains_frame = ctk.CTkFrame(self.iocs_content_frame,
                                               fg_color="#1a1a1a", corner_radius=5)
        self.iocs_domains_frame.pack(fill="x", pady=(0, 10))

        domains_label = ctk.CTkLabel(self.iocs_domains_frame, text="Domains:",
                                     font=Fonts.body_bold,
                                     text_color="white", anchor="w")
        domains_label.pack(anchor="w", padx=10, pady=(10, 5))

        self.iocs_domains_list = ctk.CTkTextbox(self.iocs_domains_frame, height=80,
                                                fg_color="#0d1520", corner_radius=5)
        self.iocs_domains_list.pack(fill="x", padx=10, pady=(0, 10))

        # ---- Notes text widget ----
        self.notes_textbox = tk.Text(
            self.notes_container,
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

        # Store screenshot image references to prevent garbage collection
        self.screenshot_images = []

        # ---- Toggle closures ----

        def toggle_files_section(event=None):
            # Prevent toggle when clicking the Add Files button
            if event and hasattr(event.widget, 'cget'):
                try:
                    if event.widget.cget('text') == "\u2795 Add Files":
                        return
                except Exception:
                    pass

            if self.files_section_visible[0]:
                self.files_list_frame.pack_forget()
                self.files_expand_indicator.configure(text="\u25b6")
                self.files_section_visible[0] = False
            else:
                self.files_list_frame.pack(fill="x", pady=(0, 10),
                                           before=self.iocs_header)
                self.files_expand_indicator.configure(text="\u25bc")
                self.files_section_visible[0] = True

        def toggle_iocs_section(event=None):
            if event and hasattr(event.widget, 'cget'):
                try:
                    if event.widget.cget('text') == "\u2795 Add IOC":
                        return
                except Exception:
                    pass

            if self.iocs_section_visible[0]:
                self.iocs_container.pack_forget()
                self.iocs_expand_indicator.configure(text="\u25b6")
                self.iocs_section_visible[0] = False
            else:
                self.iocs_container.pack(fill="x", pady=(0, 10),
                                         before=self.notes_header)
                self.iocs_expand_indicator.configure(text="\u25bc")
                self.iocs_section_visible[0] = True

        def toggle_notes_section(event=None):
            if event and hasattr(event.widget, 'cget'):
                try:
                    if event.widget.cget('text') == "\U0001f4be Save Notes":
                        return
                except Exception:
                    pass

            if self.notes_section_visible[0]:
                self.notes_container.pack_forget()
                self.notes_expand_indicator.configure(text="\u25b6")
                self.notes_section_visible[0] = False
            else:
                self.notes_container.pack(fill="both", expand=True, pady=(0, 10),
                                          before=self.screenshots_header)
                self.notes_expand_indicator.configure(text="\u25bc")
                self.notes_section_visible[0] = True

        def toggle_screenshots_section(event=None):
            if event and hasattr(event.widget, 'cget'):
                try:
                    if "Clipboard" in str(event.widget.cget('text')):
                        return
                except Exception:
                    pass

            if self.screenshots_section_visible[0]:
                self.screenshots_container.pack_forget()
                self.screenshots_expand_indicator.configure(text="\u25b6")
                self.screenshots_section_visible[0] = False
            else:
                self.screenshots_container.pack(fill="x", pady=(0, 10))
                self.screenshots_expand_indicator.configure(text="\u25bc")
                self.screenshots_section_visible[0] = True

        # Bind click events for files section
        files_header.bind("<Button-1>", toggle_files_section)
        files_header_inner.bind("<Button-1>", toggle_files_section)
        files_title.bind("<Button-1>", toggle_files_section)
        self.files_expand_indicator.bind("<Button-1>", toggle_files_section)

        # Bind click events for IOCs section
        self.iocs_header.bind("<Button-1>", toggle_iocs_section)
        iocs_header_inner.bind("<Button-1>", toggle_iocs_section)
        iocs_title.bind("<Button-1>", toggle_iocs_section)
        self.iocs_expand_indicator.bind("<Button-1>", toggle_iocs_section)

        # Bind click events for Notes section
        self.notes_header.bind("<Button-1>", toggle_notes_section)
        notes_header_inner.bind("<Button-1>", toggle_notes_section)
        notes_title.bind("<Button-1>", toggle_notes_section)
        self.notes_expand_indicator.bind("<Button-1>", toggle_notes_section)

        # Bind click events for Screenshots section
        self.screenshots_header.bind("<Button-1>", toggle_screenshots_section)
        screenshots_header_inner.bind("<Button-1>", toggle_screenshots_section)
        screenshots_title.bind("<Button-1>", toggle_screenshots_section)
        self.screenshots_expand_indicator.bind("<Button-1>", toggle_screenshots_section)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def on_activate(self):
        """Called when this view gains focus -- refresh case data."""
        self.update_display()

    # ------------------------------------------------------------------
    # Display refresh
    # ------------------------------------------------------------------

    def update_display(self):
        """Update the current case tab display."""
        if not self.current_case:
            self.case_status_label.configure(text="")
            return

        # Update status badge
        self.case_status_label.configure(text="ACTIVE", fg_color="#2D7A3E")

        # Clear and rebuild case details
        for widget in self.case_info_frame.winfo_children():
            widget.destroy()

        details = [
            ("Analyst Name:", self.current_case.get("analyst_name", "N/A")),
            ("Report URL:", self.current_case.get("report_url", "N/A")),
            ("Files:", str(len(self.current_case["files"]))),
            ("Threats:", str(self.current_case["total_threats"]))
        ]

        for i, (label, value) in enumerate(details):
            row = i // 2
            col = i % 2

            detail_frame = ctk.CTkFrame(self.case_info_frame, fg_color="transparent")
            detail_frame.grid(row=row, column=col, padx=10, pady=5, sticky="w")

            lbl = ctk.CTkLabel(detail_frame, text=label,
                               text_color="gray60", font=Fonts.helper)
            lbl.pack(anchor="w")

            val = ctk.CTkLabel(detail_frame, text=value,
                               font=Fonts.body_bold, text_color="white")
            val.pack(anchor="w")

        # Clear and rebuild files list
        for widget in self.files_list_frame.winfo_children():
            widget.destroy()

        for file_info in self.current_case["files"]:
            self.create_file_card(file_info)

        # Auto-expand Files section if there are files
        if self.current_case["files"] and not self.files_section_visible[0]:
            self.files_list_frame.pack(fill="x", pady=(0, 10),
                                       before=self.iocs_header)
            self.files_expand_indicator.configure(text="\u25bc")
            self.files_section_visible[0] = True

        # Load existing notes if available
        self.notes_textbox.delete("1.0", "end")
        if "notes" in self.current_case and self.current_case["notes"]:
            self.notes_textbox.insert("1.0", self.current_case["notes"])
            # Auto-expand Notes section if there are notes
            if not self.notes_section_visible[0]:
                self.notes_container.pack(fill="both", expand=True, pady=(0, 10),
                                          before=self.screenshots_header)
                self.notes_expand_indicator.configure(text="\u25bc")
                self.notes_section_visible[0] = True

        # Refresh IOCs display (will auto-expand if IOCs exist)
        self.refresh_iocs_display()

        # Refresh screenshots display (will auto-expand if screenshots exist)
        self.refresh_screenshots_display()

    # ------------------------------------------------------------------
    # Add files
    # ------------------------------------------------------------------

    def handle_add_files(self):
        """Handle adding files to existing case with progress window."""
        if not self.current_case:
            messagebox.showwarning("No Case", "Please create a case first")
            return

        if self.app.scan_in_progress:
            messagebox.showwarning("Scan in Progress",
                                   "Please wait for current scan to complete")
            return

        files = filedialog.askopenfilenames(title="Add files to case")
        if not files:
            return

        self.app.scan_in_progress = True
        self.app.cancel_scan = False

        # Create progress window
        self.app.create_progress_window(len(files))

        def add_files_thread():
            try:
                case_id = self.current_case["id"]
                case_dir = os.path.join(self.case_manager.case_storage_path, case_id)
                files_dir = os.path.join(case_dir, "files")

                for i, file_path in enumerate(files):
                    if self.app.cancel_scan:
                        self.root.after(0, self.app.close_progress_window)
                        self.root.after(0, lambda: messagebox.showinfo(
                            "Cancelled", "Scan cancelled by user"))
                        self.app.scan_in_progress = False
                        return

                    filename = os.path.basename(file_path)

                    # Update progress
                    self.root.after(0, self.app.update_progress, i + 1,
                                    len(files), f"Scanning: {filename}")

                    # Process file
                    file_info = self.case_manager.process_file(
                        file_path, files_dir, case_id)
                    self.current_case["files"].append(file_info)

                    # Update case statistics
                    if not file_info.get("whitelisted", False):
                        has_yara = len(file_info["yara_matches"]) > 0
                        has_thq = (file_info["thq_family"]
                                   and file_info["thq_family"] not in ["Unknown", "N/A"])
                        has_vt = file_info["vt_hits"] > 0

                        if has_yara or has_thq or has_vt:
                            self.current_case["total_threats"] += 1
                        self.current_case["total_vt_hits"] += file_info["vt_hits"]

                # Save case metadata
                self.case_manager.save_case_metadata(case_dir, self.current_case)

                # Close progress window and update display
                self.root.after(0, self.app.close_progress_window)
                self.root.after(0, self.update_display)
                self.root.after(0, lambda: messagebox.showinfo(
                    "Success",
                    f"Added {len(files)} files to case\n"
                    f"Total files: {len(self.current_case['files'])}\n"
                    f"Total threats: {self.current_case['total_threats']}"
                ))

            except Exception as e:
                self.root.after(0, self.app.close_progress_window)
                self.root.after(0, lambda: messagebox.showerror(
                    "Error", f"Failed to add files: {str(e)}"))
                import traceback
                traceback.print_exc()

            finally:
                self.app.scan_in_progress = False

        thread = threading.Thread(target=add_files_thread, daemon=True)
        thread.start()

    # ------------------------------------------------------------------
    # IOC management
    # ------------------------------------------------------------------

    def handle_add_ioc(self):
        """Show dialog to add IOC to current case."""
        if not self.current_case:
            messagebox.showwarning("No Case", "No active case to add IOC to")
            return

        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Add IOC")
        dialog.geometry("500x300")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (dialog.winfo_screenheight() // 2) - (300 // 2)
        dialog.geometry(f"500x300+{x}+{y}")

        content = ctk.CTkFrame(dialog, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=20)

        title_label = ctk.CTkLabel(content, text="Add Indicator of Compromise",
                                   font=Fonts.title_medium)
        title_label.pack(pady=(0, 15))

        type_label = ctk.CTkLabel(content, text="IOC Type:",
                                  font=Fonts.body_bold, anchor="w")
        type_label.pack(anchor="w", pady=(0, 5))

        ioc_type_var = tk.StringVar(value="urls")
        type_frame = ctk.CTkFrame(content, fg_color="transparent")
        type_frame.pack(anchor="w", pady=(0, 10))

        ctk.CTkRadioButton(type_frame, text="URL", variable=ioc_type_var,
                           value="urls",
                           fg_color=self.colors["red"]).pack(side="left", padx=(0, 10))
        ctk.CTkRadioButton(type_frame, text="IP Address", variable=ioc_type_var,
                           value="ips",
                           fg_color=self.colors["red"]).pack(side="left", padx=(0, 10))
        ctk.CTkRadioButton(type_frame, text="Domain", variable=ioc_type_var,
                           value="domains",
                           fg_color=self.colors["red"]).pack(side="left")

        value_label = ctk.CTkLabel(content, text="IOC Value:",
                                   font=Fonts.body_bold, anchor="w")
        value_label.pack(anchor="w", pady=(0, 5))

        ioc_value_entry = ctk.CTkEntry(content, width=450, height=35)
        ioc_value_entry.pack(pady=(0, 20))
        ioc_value_entry.focus()

        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(pady=(10, 0))

        def add_ioc():
            ioc_type = ioc_type_var.get()
            ioc_value = ioc_value_entry.get().strip()

            if not ioc_value:
                messagebox.showwarning("Empty Value", "Please enter an IOC value")
                return

            self.case_manager.add_ioc(ioc_type, ioc_value)
            self.refresh_iocs_display()

            messagebox.showinfo("Success",
                                f"IOC added successfully!\n\n"
                                f"Type: {ioc_type}\nValue: {ioc_value}")
            dialog.destroy()

        btn_add = ctk.CTkButton(btn_frame, text="Add IOC", command=add_ioc,
                                width=120, height=35,
                                fg_color=self.colors["red"],
                                hover_color=self.colors["red_dark"])
        btn_add.pack(side="left", padx=5)

        btn_cancel = ctk.CTkButton(btn_frame, text="Cancel",
                                   command=dialog.destroy,
                                   width=120, height=35,
                                   fg_color="gray40", hover_color="gray30")
        btn_cancel.pack(side="left", padx=5)

    def refresh_iocs_display(self):
        """Refresh the IOCs display in the Current Case tab."""
        if not self.current_case:
            return

        iocs = self.current_case.get("iocs",
                                     {"urls": [], "ips": [], "domains": []})

        # Clear existing content
        self.iocs_urls_list.delete("1.0", "end")
        self.iocs_ips_list.delete("1.0", "end")
        self.iocs_domains_list.delete("1.0", "end")

        has_iocs = bool(iocs.get("urls") or iocs.get("ips") or iocs.get("domains"))

        if iocs.get("urls"):
            self.iocs_urls_list.insert("1.0", "\n".join(iocs["urls"]))
        else:
            self.iocs_urls_list.insert("1.0", "No URLs recorded")

        if iocs.get("ips"):
            self.iocs_ips_list.insert("1.0", "\n".join(iocs["ips"]))
        else:
            self.iocs_ips_list.insert("1.0", "No IP addresses recorded")

        if iocs.get("domains"):
            self.iocs_domains_list.insert("1.0", "\n".join(iocs["domains"]))
        else:
            self.iocs_domains_list.insert("1.0", "No domains recorded")

        # Auto-expand IOCs section if there are IOCs
        if has_iocs and not self.iocs_section_visible[0]:
            self.iocs_container.pack(fill="x", pady=(0, 10),
                                     before=self.notes_header)
            self.iocs_expand_indicator.configure(text="\u25bc")
            self.iocs_section_visible[0] = True

    # ------------------------------------------------------------------
    # Notes
    # ------------------------------------------------------------------

    def handle_save_notes(self):
        """Save notes to the current case."""
        if not self.current_case:
            messagebox.showwarning("No Case", "No active case to save notes to")
            return

        notes = self.notes_textbox.get("1.0", "end-1c").strip()

        if not notes:
            messagebox.showwarning("Empty Notes",
                                   "Please enter some notes before saving")
            return

        try:
            self.current_case["notes"] = notes

            case_dir = os.path.join(self.case_manager.case_storage_path,
                                    self.current_case["id"])

            self.case_manager.save_case_metadata(case_dir, self.current_case)
            self.case_manager.save_case_notes(case_dir, notes)

            notes_file = os.path.join(case_dir, "case_notes.txt")

            messagebox.showinfo(
                "Success",
                f"Notes saved successfully!\n\n"
                f"Location:\n{notes_file}\n\n"
                f"Characters: {len(notes)}"
            )

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save notes: {str(e)}")

    # ------------------------------------------------------------------
    # Screenshots
    # ------------------------------------------------------------------

    def attach_screenshot_from_clipboard(self):
        """Attach a screenshot from the clipboard to the current case."""
        if not self.current_case:
            messagebox.showwarning("No Case",
                                   "No active case to attach screenshot to")
            return

        try:
            from PIL import ImageGrab

            clipboard_image = ImageGrab.grabclipboard()

            if clipboard_image is None:
                messagebox.showwarning(
                    "No Image",
                    "No image found in clipboard.\n\n"
                    "Use the Snipping Tool (Win+Shift+S) to capture a screenshot, "
                    "then click 'Paste from Clipboard'."
                )
                return

            if not isinstance(clipboard_image, Image.Image):
                if isinstance(clipboard_image, list) and len(clipboard_image) > 0:
                    try:
                        clipboard_image = Image.open(clipboard_image[0])
                    except Exception:
                        messagebox.showwarning("Invalid Image",
                                               "Clipboard does not contain a valid image")
                        return
                else:
                    messagebox.showwarning("Invalid Image",
                                           "Clipboard does not contain a valid image")
                    return

            case_dir = os.path.join(self.case_manager.case_storage_path,
                                    self.current_case["id"])
            screenshots_dir = os.path.join(case_dir, "screenshots")
            os.makedirs(screenshots_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            screenshot_filename = f"screenshot_{timestamp}.png"
            screenshot_path = os.path.join(screenshots_dir, screenshot_filename)

            clipboard_image.save(screenshot_path, "PNG")

            if "screenshots" not in self.current_case:
                self.current_case["screenshots"] = []

            self.current_case["screenshots"].append({
                "filename": screenshot_filename,
                "path": screenshot_path,
                "timestamp": datetime.now().isoformat(),
                "width": clipboard_image.width,
                "height": clipboard_image.height
            })

            self.case_manager.save_case_metadata(case_dir, self.current_case)

            # Copy screenshot to network case folder if enabled
            network_copy_msg = ""
            if self.current_case.get("network_case_path"):
                try:
                    network_path = self.current_case["network_case_path"]
                    network_screenshots_dir = os.path.join(network_path, "screenshots")
                    os.makedirs(network_screenshots_dir, exist_ok=True)
                    network_screenshot_path = os.path.join(network_screenshots_dir,
                                                           screenshot_filename)
                    shutil.copy2(screenshot_path, network_screenshot_path)
                    network_copy_msg = "\n\nAlso copied to network folder."
                except Exception as e:
                    print(f"Warning: Could not copy screenshot to network folder: {e}")

            self.refresh_screenshots_display()

            messagebox.showinfo(
                "Screenshot Attached",
                f"Screenshot saved successfully!\n\n"
                f"Size: {clipboard_image.width} x {clipboard_image.height}\n"
                f"File: {screenshot_filename}{network_copy_msg}"
            )

        except ImportError:
            messagebox.showerror(
                "Missing Dependency",
                "PIL/Pillow is required for clipboard image capture.\n"
                "Install with: pip install Pillow"
            )
        except Exception as e:
            messagebox.showerror("Error",
                                 f"Failed to attach screenshot: {str(e)}")
            import traceback
            traceback.print_exc()

    def refresh_screenshots_display(self):
        """Refresh the screenshots display in the Current Case tab."""
        for widget in self.screenshots_display_frame.winfo_children():
            widget.destroy()

        self.screenshot_images = []

        if (not self.current_case
                or "screenshots" not in self.current_case
                or not self.current_case["screenshots"]):
            placeholder = ctk.CTkLabel(
                self.screenshots_display_frame,
                text="No screenshots attached. Use 'Paste from Clipboard' to add screenshots.",
                font=Fonts.body, text_color="gray")
            placeholder.pack(pady=20)
            return

        # Auto-expand Screenshots section if there are screenshots
        if not self.screenshots_section_visible[0]:
            self.screenshots_container.pack(fill="x", pady=(0, 10))
            self.screenshots_expand_indicator.configure(text="\u25bc")
            self.screenshots_section_visible[0] = True

        gallery_frame = ctk.CTkFrame(self.screenshots_display_frame,
                                     fg_color="transparent")
        gallery_frame.pack(fill="x", padx=5, pady=10)

        for i, screenshot_info in enumerate(self.current_case["screenshots"]):
            screenshot_path = screenshot_info.get("path", "")

            if not os.path.exists(screenshot_path):
                continue

            screenshot_frame = ctk.CTkFrame(gallery_frame, fg_color="#1a1a1a",
                                            corner_radius=8)
            screenshot_frame.pack(side="left", padx=5, pady=5)

            try:
                pil_image = Image.open(screenshot_path)

                max_height = 120
                ratio = max_height / pil_image.height
                new_width = int(pil_image.width * ratio)
                if new_width > 200:
                    new_width = 200
                    ratio = new_width / pil_image.width
                    max_height = int(pil_image.height * ratio)

                thumbnail = pil_image.copy()
                thumbnail.thumbnail((new_width, max_height),
                                    Image.Resampling.LANCZOS)

                ctk_image = ctk.CTkImage(light_image=thumbnail,
                                         dark_image=thumbnail,
                                         size=(thumbnail.width, thumbnail.height))

                self.screenshot_images.append(ctk_image)

                img_label = ctk.CTkLabel(screenshot_frame, image=ctk_image,
                                         text="", cursor="hand2")
                img_label.pack(padx=8, pady=(8, 4))
                img_label.bind("<Button-1>",
                               lambda e, path=screenshot_path: self.open_screenshot(path))

                btn_delete = ctk.CTkButton(
                    screenshot_frame, text="Delete",
                    command=lambda idx=i: self.delete_screenshot(idx),
                    width=70, height=25,
                    fg_color=self.colors["red"],
                    hover_color=self.colors["red_dark"],
                    font=Fonts.body)
                btn_delete.pack(pady=(0, 8))

            except Exception as e:
                print(f"Error loading screenshot {screenshot_path}: {e}")
                error_label = ctk.CTkLabel(
                    screenshot_frame,
                    text=f"Error loading: {screenshot_info.get('filename', 'Unknown')}",
                    font=Fonts.body, text_color="red")
                error_label.pack(pady=10)

    def open_screenshot(self, path):
        """Open a screenshot with the default image viewer."""
        try:
            if platform.system() == "Windows":
                os.startfile(path)
            elif platform.system() == "Darwin":
                subprocess.run(["open", path])
            else:
                subprocess.run(["xdg-open", path])
        except Exception as e:
            messagebox.showerror("Error",
                                 f"Failed to open screenshot: {str(e)}")

    def delete_screenshot(self, index):
        """Delete a screenshot from the case."""
        if not self.current_case or "screenshots" not in self.current_case:
            return

        if index >= len(self.current_case["screenshots"]):
            return

        screenshot_info = self.current_case["screenshots"][index]
        filename = screenshot_info.get("filename", "this screenshot")

        result = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete {filename}?"
        )

        if not result:
            return

        try:
            screenshot_path = screenshot_info.get("path", "")
            if os.path.exists(screenshot_path):
                os.remove(screenshot_path)

            self.current_case["screenshots"].pop(index)

            case_dir = os.path.join(self.case_manager.case_storage_path,
                                    self.current_case["id"])
            self.case_manager.save_case_metadata(case_dir, self.current_case)

            self.refresh_screenshots_display()

            messagebox.showinfo("Deleted",
                                f"Screenshot '{filename}' deleted successfully")

        except Exception as e:
            messagebox.showerror("Error",
                                 f"Failed to delete screenshot: {str(e)}")

    # ------------------------------------------------------------------
    # File cards
    # ------------------------------------------------------------------

    def create_file_card(self, file_info):
        """Create an expandable card for displaying file information."""
        yara_matches = file_info.get("yara_matches", [])
        thq_family = file_info.get("thq_family", "Unknown")
        is_whitelisted = file_info.get("whitelisted", False)
        has_threats = len(yara_matches) > 0 or file_info.get("vt_hits", 0) > 0

        # Determine card color
        if is_whitelisted:
            card_color = "#1a4d2e"  # Dark green for whitelisted
        elif has_threats:
            card_color = "#5c1c1c"  # Dark red for threats
        else:
            card_color = "#2a2a2a"  # Dark gray for clean

        card_frame = ctk.CTkFrame(
            self.files_list_frame,
            corner_radius=8,
            fg_color=card_color,
            cursor="hand2"
        )
        card_frame.pack(fill="x", padx=10, pady=5)

        # Header (always visible)
        header_frame = ctk.CTkFrame(card_frame, fg_color="transparent",
                                    cursor="hand2")
        header_frame.pack(fill="x", padx=15, pady=12)
        header_frame.grid_columnconfigure(0, weight=1)

        # Left side - file info
        left_frame = ctk.CTkFrame(header_frame, fg_color="transparent",
                                  cursor="hand2")
        left_frame.grid(row=0, column=0, sticky="w")

        name_label = ctk.CTkLabel(
            left_frame, text=file_info["filename"],
            font=Fonts.title_medium, text_color="white", cursor="hand2"
        )
        name_label.pack(anchor="w")

        # YARA and THQ matches display in one line
        if is_whitelisted:
            info_line = "\u2705 BENIGN (Whitelisted)"
            label_color = "#2ecc71"
        else:
            yara_display = self.case_manager.get_yara_display_text(yara_matches)
            thq_display = (thq_family
                           if thq_family and thq_family != "Unknown"
                           else "N/A")
            info_line = f"YARA: {yara_display}  |  THQ: {thq_display}"

            has_yara = bool(yara_matches)
            has_thq = thq_family and thq_family not in ["Unknown", "N/A"]
            if has_yara:
                label_color = self.colors["red"]
            elif has_thq:
                label_color = "#FF8C00"
            else:
                label_color = "gray60"

        yara_thq_label = ctk.CTkLabel(
            left_frame, text=info_line,
            text_color=label_color,
            font=Fonts.body_bold, cursor="hand2"
        )
        yara_thq_label.pack(anchor="w", pady=(3, 0))

        # File size and timestamp
        size_kb = file_info.get("file_size", 0) / 1024
        info_text = (f"{size_kb:.2f} KB | "
                     f"{datetime.fromisoformat(file_info['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
        info_label = ctk.CTkLabel(
            left_frame, text=info_text,
            text_color="gray60", font=Fonts.helper, cursor="hand2"
        )
        info_label.pack(anchor="w", pady=(2, 0))

        # Right side - expand indicator
        right_frame = ctk.CTkFrame(header_frame, fg_color="transparent",
                                   cursor="hand2")
        right_frame.grid(row=0, column=1, sticky="e", padx=(10, 0))

        details_visible = [False]
        details_frame = ctk.CTkFrame(card_frame, fg_color="#0d1520", height=200)

        expand_indicator = ctk.CTkLabel(
            right_frame, text="\u25bc",
            font=Fonts.body_large, text_color="gray60", cursor="hand2"
        )
        expand_indicator.pack(side="top")

        # Buttons row (horizontal layout below header)
        buttons_row = ctk.CTkFrame(card_frame, fg_color="transparent")
        buttons_row.pack(fill="x", padx=15, pady=(0, 12))

        # -- Copy details button --
        def copy_details(event):
            copy_text = (f"File Name: {file_info['filename']}\n"
                         f"MD5: {file_info['md5']}\n"
                         f"SHA256: {file_info['sha256']}\n"
                         f"File Size: {file_info['file_size']} bytes")

            self.root.clipboard_clear()
            self.root.clipboard_append(copy_text)
            self.root.update()

            original_text = copy_btn.cget("text")
            copy_btn.configure(text="\u2713 Copied!")
            self.root.after(1500, lambda: copy_btn.configure(text=original_text))
            return "break"

        copy_btn = ctk.CTkButton(
            buttons_row, text="\U0001f4cb Copy",
            width=100, height=28, font=Fonts.helper,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            cursor="hand2"
        )
        copy_btn.pack(side="left", padx=(0, 5))
        copy_btn.bind("<Button-1>", copy_details)

        # -- View Strings button --
        def view_strings_click(event):
            file_path = file_info.get('storage_path', '')
            if file_path and os.path.exists(file_path):
                self.app.view_file_strings(file_path, file_info['filename'])
            else:
                messagebox.showerror("File Not Found",
                                     f"File not found: {file_path}")
            return "break"

        view_strings_btn = ctk.CTkButton(
            buttons_row, text="\U0001f4c4 Strings",
            width=100, height=28, font=Fonts.helper,
            fg_color="transparent", border_width=2,
            border_color=self.colors["red"],
            hover_color=self.colors["navy"],
            cursor="hand2"
        )
        view_strings_btn.pack(side="left", padx=5)
        view_strings_btn.bind("<Button-1>", view_strings_click)

        # -- View File button --
        def view_file_click(event):
            file_path = file_info.get('storage_path', '')
            if file_path and os.path.exists(file_path):
                viewer = get_viewer_executor()
                info = viewer.get_file_info(file_path)

                if info.get('is_text', False):
                    self.app.view_file_text(file_path, file_info['filename'])
                else:
                    self.app.view_file_hex(file_path, file_info['filename'])
            else:
                messagebox.showerror("File Not Found",
                                     f"File not found: {file_path}")
            return "break"

        view_file_btn = ctk.CTkButton(
            buttons_row, text="\U0001f441 View",
            width=90, height=28, font=Fonts.helper,
            fg_color="transparent", border_width=2,
            border_color=self.colors["red"],
            hover_color=self.colors["navy"],
            cursor="hand2"
        )
        view_file_btn.pack(side="left", padx=5)
        view_file_btn.bind("<Button-1>", view_file_click)

        # -- Execute File button --
        def execute_file_click(event):
            file_path = file_info.get('storage_path', '')
            if file_path and os.path.exists(file_path):
                self.app.execute_file(file_path, file_info['filename'])
            else:
                messagebox.showerror("File Not Found",
                                     f"File not found: {file_path}")
            return "break"

        execute_file_btn = ctk.CTkButton(
            buttons_row, text="\u25b6\ufe0f Execute",
            width=110, height=28, font=Fonts.helper,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            cursor="hand2"
        )
        execute_file_btn.pack(side="left", padx=5)
        execute_file_btn.bind("<Button-1>", execute_file_click)

        # -- Execute (Suspended) button --
        def execute_suspended_click(event):
            file_path = file_info.get('storage_path', '')
            if file_path and os.path.exists(file_path):
                if file_path.lower().endswith(('.exe', '.msi')):
                    self.app.execute_file(file_path, file_info['filename'],
                                          suspended=True)
                else:
                    messagebox.showinfo(
                        "Not Supported",
                        "Suspended execution is only supported for EXE and MSI files."
                    )
            else:
                messagebox.showerror("File Not Found",
                                     f"File not found: {file_path}")
            return "break"

        execute_suspended_btn = ctk.CTkButton(
            buttons_row, text="\u23f8 Suspended",
            width=120, height=28, font=Fonts.helper,
            fg_color="transparent", border_width=2,
            border_color="#FFA500", text_color="#FFA500",
            hover_color=self.colors["navy"],
            cursor="hand2"
        )
        execute_suspended_btn.pack(side="left", padx=5)
        execute_suspended_btn.bind("<Button-1>", execute_suspended_click)

        # -- Delete File button --
        def delete_file_click(event):
            file_path = file_info.get('storage_path', '')
            file_name = file_info['filename']

            result = messagebox.askyesno(
                "Delete File",
                f"Are you sure you want to delete this file from the case?\n\n"
                f"{file_name}\n\nThis will remove it from disk and the case.",
                icon='warning'
            )

            if result:
                self.delete_file_from_case(file_info, card_frame)
            return "break"

        delete_btn = ctk.CTkButton(
            buttons_row, text="\U0001f5d1 Delete",
            width=100, height=28, font=Fonts.helper,
            fg_color="#8B0000",
            hover_color="#5c0000",
            cursor="hand2"
        )
        delete_btn.pack(side="left", padx=5)
        delete_btn.bind("<Button-1>", delete_file_click)

        # -- Toggle details closure --
        def toggle_details(event=None):
            if details_visible[0]:
                details_frame.pack_forget()
                expand_indicator.configure(text="\u25bc")
                details_visible[0] = False
            else:
                if len(details_frame.winfo_children()) == 0:
                    self.populate_file_details(details_frame, file_info)
                details_frame.pack(fill="both", expand=True, padx=15, pady=(0, 12))
                expand_indicator.configure(text="\u25b2")
                details_visible[0] = True
            card_frame.update_idletasks()
            self.root.update_idletasks()

        # Bind click events to all elements
        card_frame.bind("<Button-1>", toggle_details)
        header_frame.bind("<Button-1>", toggle_details)
        left_frame.bind("<Button-1>", toggle_details)
        right_frame.bind("<Button-1>", toggle_details)
        name_label.bind("<Button-1>", toggle_details)
        yara_thq_label.bind("<Button-1>", toggle_details)
        info_label.bind("<Button-1>", toggle_details)
        expand_indicator.bind("<Button-1>", toggle_details)

    def populate_file_details(self, parent_frame, file_info):
        """Populate the detailed information section."""
        details_text_frame = ctk.CTkFrame(parent_frame, fg_color="gray10")
        details_text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        details_text = self.case_manager.format_file_details(file_info)

        text_widget = tk.Text(
            details_text_frame,
            wrap="none",
            bg="#1a1a1a",
            fg="#ffffff",
            font=Fonts.monospace(10),
            height=12,
            relief="flat",
            padx=10,
            pady=10,
            cursor="arrow"
        )

        # Configure tag for clickable links
        text_widget.tag_config("link", foreground="#4a9eff", underline=True)
        text_widget.tag_bind("link", "<Enter>",
                             lambda e: text_widget.config(cursor="hand2"))
        text_widget.tag_bind("link", "<Leave>",
                             lambda e: text_widget.config(cursor="arrow"))

        text_widget.insert("1.0", details_text)

        # Find and tag VT link if present
        vt_link = file_info.get('vt_link', '')
        if vt_link and vt_link != 'N/A':
            start_pos = "1.0"
            while True:
                start_pos = text_widget.search(vt_link, start_pos, tk.END)
                if not start_pos:
                    break
                end_pos = f"{start_pos}+{len(vt_link)}c"
                text_widget.tag_add("link", start_pos, end_pos)

                def open_link(event, url=vt_link):
                    webbrowser.open(url)
                    return "break"

                text_widget.tag_bind("link", "<Button-1>", open_link)
                start_pos = end_pos

        text_widget.configure(state="disabled")  # Make read-only
        text_widget.pack(fill="both", expand=True)

    def delete_file_from_case(self, file_info, card_frame):
        """Delete a file from the current case.

        Args:
            file_info: Dictionary containing file information
            card_frame: The GUI frame/card to remove
        """
        try:
            file_path = file_info.get('storage_path', '')
            file_name = file_info['filename']

            # Remove file from disk
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
                print(f"\u2713 Deleted file: {file_path}")

                # Also remove the _details.json file
                details_path = file_path + "_details.json"
                if os.path.exists(details_path):
                    os.remove(details_path)

                # Remove decoded file if exists
                decoded_path = file_path + "_decoded.txt"
                if os.path.exists(decoded_path):
                    os.remove(decoded_path)

            # Remove from current case files list
            if file_info in self.current_case["files"]:
                self.current_case["files"].remove(file_info)

            # Update case statistics
            if not file_info.get("whitelisted", False):
                yara_matches = file_info.get("yara_matches", [])
                if yara_matches:
                    self.current_case["files_with_yara"] = max(
                        0, self.current_case.get("files_with_yara", 0) - 1)

                thq_family = file_info.get("thq_family", "")
                if thq_family and thq_family not in ["Unknown", "N/A"]:
                    self.current_case["files_with_thq"] = max(
                        0, self.current_case.get("files_with_thq", 0) - 1)

                vt_hits = file_info.get("vt_hits", 0)
                if vt_hits > 0:
                    self.current_case["files_with_vt"] = max(
                        0, self.current_case.get("files_with_vt", 0) - 1)
                    self.current_case["total_vt_hits"] = max(
                        0, self.current_case.get("total_vt_hits", 0) - vt_hits)

            # Save updated case metadata
            if self.current_case and self.current_case.get("id"):
                case_dir = os.path.join(self.case_manager.case_storage_path,
                                        self.current_case["id"])
                self.case_manager.save_case_metadata(case_dir, self.current_case)

            # Remove the card from display
            card_frame.destroy()

            # Update stats display
            self.update_display()

            messagebox.showinfo("File Deleted",
                                f"Successfully deleted {file_name} from the case.")

        except Exception as e:
            messagebox.showerror("Delete Error",
                                 f"Failed to delete file:\n\n{str(e)}")
