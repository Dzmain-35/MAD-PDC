"""
New Case View for MAD - Case creation form with file upload/URL download.
Extracted from MAD.py create_new_case_tab() and related methods.
"""

import os
import platform
import subprocess
import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog
from datetime import datetime
from PIL import Image
from typography import Fonts
from views.base_view import BaseView


class NewCaseView(BaseView):
    """New case creation form with file upload and URL download."""

    def __init__(self, parent, app, colors):
        super().__init__(parent, app, colors)
        # Form widgets stored as instance vars for access by handlers
        self.analyst_name_entry = None
        self.report_url_entry = None
        self.url_entry = None
        self.upload_method = None
        self.btn_upload = None
        self.url_input_frame = None
        self.status_label = None
        self._build()

    def _build(self):
        """Build the new case form UI."""
        frame = self.frame
        form_entry_width = 500 if self.is_large_screen else 320
        form_btn_width = 500 if self.is_large_screen else 320

        # Center container
        center_container = ctk.CTkFrame(frame, fg_color="transparent")
        center_container.place(relx=0.5, rely=0.5, anchor="center")

        # Logo and branding section
        logo_frame = ctk.CTkFrame(center_container, fg_color="transparent")
        logo_frame.pack(pady=(0, 30))

        # Load and display the M.A.D. logo image
        image_loaded = False
        try:
            possible_paths = [
                "image.png",
                os.path.join(os.getcwd(), "image.png"),
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "image.png"),
                os.path.join(os.path.expanduser("~"), "Desktop", "MAD", "image.png"),
                r"C:\Users\REM\Desktop\MAD\image.png"
            ]

            logo_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    logo_path = path
                    break

            if logo_path and os.path.exists(logo_path):
                pil_image = Image.open(logo_path)
                max_size = 350 if self.is_large_screen else 190
                pil_image.thumbnail((max_size, max_size), Image.Resampling.LANCZOS)

                logo_image = ctk.CTkImage(
                    light_image=pil_image,
                    dark_image=pil_image,
                    size=(pil_image.width, pil_image.height)
                )

                logo_label = ctk.CTkLabel(logo_frame, image=logo_image, text="")
                logo_label.image = logo_image
                logo_label.pack()
                image_loaded = True

        except Exception as e:
            print(f"ERROR loading logo image: {e}")

        if not image_loaded:
            self._create_fallback_logo(logo_frame)

        # Title section
        title_frame = ctk.CTkFrame(center_container, fg_color="transparent")
        title_frame.pack(pady=(20, 20))

        title = ctk.CTkLabel(title_frame, text="New Malware Case",
                             font=Fonts.header_main, text_color="white")
        title.pack()

        separator = ctk.CTkFrame(title_frame, height=3, fg_color=self.colors["red"])
        separator.pack(fill="x", pady=(10, 0))

        # Form container
        form_container = ctk.CTkFrame(center_container, fg_color="transparent")
        form_container.pack(pady=(20, 20))

        # Analyst Name input
        analyst_label = ctk.CTkLabel(form_container, text="Analyst Name",
                                     font=Fonts.label_large, text_color="white", anchor="w")
        analyst_label.pack(anchor="w", padx=5, pady=(0, 5))

        self.analyst_name_entry = ctk.CTkEntry(
            form_container, width=form_entry_width, height=40,
            placeholder_text="Enter your name", font=Fonts.body_large,
            fg_color=self.colors["navy"], border_color=self.colors["red"], border_width=2)
        self.analyst_name_entry.pack(padx=5, pady=(0, 15))

        # Report URL input
        report_label = ctk.CTkLabel(form_container, text="Report URL",
                                    font=Fonts.label_large, text_color="white", anchor="w")
        report_label.pack(anchor="w", padx=5, pady=(0, 5))

        self.report_url_entry = ctk.CTkEntry(
            form_container, width=form_entry_width, height=40,
            placeholder_text="Enter report URL", font=Fonts.body_large,
            fg_color=self.colors["navy"], border_color=self.colors["red"], border_width=2)
        self.report_url_entry.pack(padx=5, pady=(0, 20))

        # Upload method selection
        upload_method_frame = ctk.CTkFrame(center_container, fg_color="transparent")
        upload_method_frame.pack(pady=(10, 10))

        method_label = ctk.CTkLabel(upload_method_frame, text="Select Upload Method:",
                                    font=Fonts.label_large, text_color="white")
        method_label.pack(pady=(0, 10))

        self.upload_method = tk.StringVar(value="file")

        radio_frame = ctk.CTkFrame(upload_method_frame, fg_color="transparent")
        radio_frame.pack()

        self.radio_file = ctk.CTkRadioButton(
            radio_frame, text="Upload Files", variable=self.upload_method,
            value="file", command=self._on_upload_method_change,
            font=Fonts.body_large, fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"])
        self.radio_file.pack(side="left", padx=20)

        self.radio_url = ctk.CTkRadioButton(
            radio_frame, text="Download from URLs", variable=self.upload_method,
            value="url", command=self._on_upload_method_change,
            font=Fonts.body_large, fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"])
        self.radio_url.pack(side="left", padx=20)

        # URL input area (initially hidden)
        self.url_input_frame = ctk.CTkFrame(center_container, fg_color="transparent")

        url_label = ctk.CTkLabel(self.url_input_frame, text="Download URL",
                                 font=Fonts.label_large, text_color="white")
        url_label.pack(anchor="w", pady=(0, 5))

        self.url_entry = ctk.CTkEntry(
            self.url_input_frame, placeholder_text="Enter URL to download file from...",
            height=45, width=form_entry_width, font=Fonts.body_large,
            fg_color="gray20", border_color=self.colors["red"], border_width=2)
        self.url_entry.pack(fill="x")

        # Upload button
        self.btn_upload = ctk.CTkButton(
            center_container, text="Upload File to Start Case",
            command=self._handle_upload, height=50, width=form_btn_width,
            font=Fonts.title_medium, fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"], corner_radius=8)
        self.btn_upload.pack(pady=(10, 10))

        # Status label
        self.status_label = ctk.CTkLabel(center_container, text="",
                                         font=Fonts.body, text_color="white")
        self.status_label.pack(pady=10)

    def _create_fallback_logo(self, parent_frame):
        """Create fallback text-based logo if image.png is not found."""
        logo_shield = ctk.CTkLabel(parent_frame, text="\U0001f6e1",
                                   font=Fonts.logo_emoji,
                                   text_color=self.colors["red"])
        logo_shield.pack(side="left", padx=(0, 20))

        logo_text_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        logo_text_frame.pack(side="left")

        logo_main = ctk.CTkLabel(logo_text_frame, text="M.A.D.",
                                 font=Fonts.logo_main, text_color="white")
        logo_main.pack(anchor="w")

        logo_subtitle = ctk.CTkLabel(logo_text_frame, text="MALWARE ANALYSIS\nDASHBOARD",
                                     font=Fonts.logo_subtitle, text_color="white",
                                     justify="left")
        logo_subtitle.pack(anchor="w")

    def _on_upload_method_change(self):
        """Handle upload method radio button change."""
        method = self.upload_method.get()
        if method == "url":
            self.url_input_frame.pack(pady=(10, 0), before=self.btn_upload)
            self.btn_upload.configure(text="Download and Start Case")
        else:
            self.url_input_frame.pack_forget()
            self.btn_upload.configure(text="Upload File to Start Case")

    def _handle_upload(self):
        """Handle file upload or URL download for new case."""
        if self.app.scan_in_progress:
            messagebox.showwarning("Scan in Progress", "Please wait for current scan to complete")
            return

        # Force NTP clock resync to handle VM snapshot date staleness
        self._sync_clock_before_case()

        # Validate analyst name and report URL
        analyst_name = self.analyst_name_entry.get().strip()
        report_url = self.report_url_entry.get().strip()

        if not analyst_name:
            messagebox.showwarning("Missing Information", "Please enter an Analyst Name")
            self.analyst_name_entry.focus()
            return

        if not report_url:
            messagebox.showwarning("Missing Information", "Please enter a Report URL")
            self.report_url_entry.focus()
            return

        # Check upload method
        method = self.upload_method.get()

        if method == "url":
            download_url = self.url_entry.get().strip()
            if not download_url:
                messagebox.showwarning("Missing URL", "Please enter a URL to download")
                self.url_entry.focus()
                return

            if not download_url.startswith(('http://', 'https://')):
                download_url = 'https://' + download_url

            self.app.process_new_case_urls([download_url], analyst_name, report_url)
        else:
            files = filedialog.askopenfilenames(title="Select files to analyze")
            if not files:
                return
            self.app.process_new_case_files(list(files), analyst_name, report_url)

    def _sync_clock_before_case(self):
        """Auto-sync Windows system clock via NTP before creating a case."""
        if platform.system() != "Windows":
            return

        self.status_label.configure(text="Syncing system clock...", text_color="#fbbf24")
        self.root.update_idletasks()

        steps = [
            (["net", "stop", "w32time"], "Stopping Windows Time service"),
            (["w32tm", "/unregister"], "Unregistering time service"),
            (["w32tm", "/register"], "Registering time service"),
            (["net", "start", "w32time"], "Starting Windows Time service"),
            (["w32tm", "/resync", "/force"], "Forcing NTP resync"),
        ]

        errors = []
        for cmd, description in steps:
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=30,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                if result.returncode != 0 and cmd[0] != "net":
                    errors.append(f"{description}: {result.stderr.strip() or result.stdout.strip()}")
            except FileNotFoundError:
                errors.append(f"Command not found: {cmd[0]}")
                break
            except subprocess.TimeoutExpired:
                errors.append(f"{description}: timed out")
            except Exception as e:
                errors.append(f"{description}: {e}")

        if errors:
            msg = "; ".join(errors)
            print(f"Clock sync failed: {msg}")
            self.status_label.configure(text=f"Clock sync skipped ({msg})", text_color="#f97316")
        else:
            print(f"Clock resynced at {datetime.now().strftime('%m/%d/%Y %H:%M:%S')}")
            self.status_label.configure(
                text=f"Clock synced: {datetime.now().strftime('%m/%d/%Y %H:%M:%S')}",
                text_color="#22c55e")

        # Update the header date display
        self.app._update_date_indicator()

        # Persist as latest known date
        self.settings_manager.set("vm_snapshot.last_known_date",
                                  datetime.now().date().isoformat())
        self.settings_manager.save_settings()

    def clear_form(self):
        """Clear form fields after successful case creation."""
        self.analyst_name_entry.delete(0, 'end')
        self.report_url_entry.delete(0, 'end')
        if self.url_entry:
            self.url_entry.delete(0, 'end')
