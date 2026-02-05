"""
New Case Tab
Tab for creating new malware analysis cases.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image
import os
from typing import TYPE_CHECKING

from typography import Fonts
from .base_tab import BaseTab

if TYPE_CHECKING:
    from ui.app import ForensicAnalysisGUI


class NewCaseTab(BaseTab):
    """Tab for creating new malware analysis cases"""

    def __init__(self, app: 'ForensicAnalysisGUI', parent: ctk.CTkFrame):
        super().__init__(app, parent)
        self.analyst_name_entry = None
        self.report_url_entry = None
        self.upload_method = None
        self.url_input_frame = None
        self.url_input_textbox = None
        self.btn_upload = None
        self.status_label = None
        self.radio_file = None
        self.radio_url = None

    def create(self) -> ctk.CTkFrame:
        """Create the New Case tab interface with M.A.D. branding"""
        self.frame = ctk.CTkFrame(self.parent, fg_color=self.colors["dark_blue"])

        # Center container
        center_container = ctk.CTkFrame(self.frame, fg_color="transparent")
        center_container.place(relx=0.5, rely=0.5, anchor="center")

        # Logo and branding section
        logo_frame = ctk.CTkFrame(center_container, fg_color="transparent")
        logo_frame.pack(pady=(0, 30))

        # Load and display the M.A.D. logo image
        image_loaded = self._load_logo(logo_frame)

        # Fallback to text-based logo if image not found
        if not image_loaded:
            self._create_fallback_logo(logo_frame)

        # Title section
        title_frame = ctk.CTkFrame(center_container, fg_color="transparent")
        title_frame.pack(pady=(20, 20))

        title = ctk.CTkLabel(
            title_frame,
            text="New Malware Case",
            font=Fonts.header_main,
            text_color="white"
        )
        title.pack()

        # Separator line
        separator = ctk.CTkFrame(title_frame, height=3, fg_color=self.colors["red"])
        separator.pack(fill="x", pady=(10, 0))

        # Form container
        form_container = ctk.CTkFrame(center_container, fg_color="transparent")
        form_container.pack(pady=(20, 20))

        # Analyst Name input
        analyst_label = ctk.CTkLabel(
            form_container,
            text="Analyst Name",
            font=Fonts.label_large,
            text_color="white",
            anchor="w"
        )
        analyst_label.pack(anchor="w", padx=5, pady=(0, 5))

        self.analyst_name_entry = ctk.CTkEntry(
            form_container,
            width=400,
            height=40,
            placeholder_text="Enter your name",
            font=Fonts.body_large,
            fg_color=self.colors["navy"],
            border_color=self.colors["red"],
            border_width=2
        )
        self.analyst_name_entry.pack(padx=5, pady=(0, 15))

        # Report URL input
        report_label = ctk.CTkLabel(
            form_container,
            text="Report URL",
            font=Fonts.label_large,
            text_color="white",
            anchor="w"
        )
        report_label.pack(anchor="w", padx=5, pady=(0, 5))

        self.report_url_entry = ctk.CTkEntry(
            form_container,
            width=400,
            height=40,
            placeholder_text="Enter report URL",
            font=Fonts.body_large,
            fg_color=self.colors["navy"],
            border_color=self.colors["red"],
            border_width=2
        )
        self.report_url_entry.pack(padx=5, pady=(0, 20))

        # Upload method selection
        upload_method_frame = ctk.CTkFrame(center_container, fg_color="transparent")
        upload_method_frame.pack(pady=(10, 10))

        method_label = ctk.CTkLabel(
            upload_method_frame,
            text="Select Upload Method:",
            font=Fonts.label_large,
            text_color="white"
        )
        method_label.pack(pady=(0, 10))

        # Radio button variable
        self.upload_method = tk.StringVar(value="file")

        radio_frame = ctk.CTkFrame(upload_method_frame, fg_color="transparent")
        radio_frame.pack()

        self.radio_file = ctk.CTkRadioButton(
            radio_frame,
            text="Upload Files",
            variable=self.upload_method,
            value="file",
            command=self._on_upload_method_change,
            font=Fonts.body_large,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"]
        )
        self.radio_file.pack(side="left", padx=20)

        self.radio_url = ctk.CTkRadioButton(
            radio_frame,
            text="Download from URLs",
            variable=self.upload_method,
            value="url",
            command=self._on_upload_method_change,
            font=Fonts.body_large,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"]
        )
        self.radio_url.pack(side="left", padx=20)

        # URL input area (initially hidden)
        self.url_input_frame = ctk.CTkFrame(
            center_container, fg_color=self.colors["navy"], corner_radius=8
        )

        url_input_label = ctk.CTkLabel(
            self.url_input_frame,
            text="Enter URLs (one per line):",
            font=Fonts.body_bold,
            text_color="white",
            anchor="w"
        )
        url_input_label.pack(anchor="w", padx=15, pady=(15, 5))

        self.url_input_textbox = tk.Text(
            self.url_input_frame,
            wrap="none",
            bg="#1a1a1a",
            fg="#ffffff",
            font=Fonts.text_input(),
            relief="flat",
            padx=10,
            pady=10,
            height=6,
            width=48
        )
        self.url_input_textbox.pack(padx=15, pady=(0, 15))

        # Upload button
        self.btn_upload = ctk.CTkButton(
            center_container,
            text="Upload File to Start Case",
            command=self._handle_upload,
            height=50,
            width=400,
            font=Fonts.title_medium,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            corner_radius=8
        )
        self.btn_upload.pack(pady=(10, 10))

        # Status label for feedback
        self.status_label = ctk.CTkLabel(
            center_container,
            text="",
            font=Fonts.body,
            text_color="white"
        )
        self.status_label.pack(pady=10)

        # Store references in app for backward compatibility
        self.app.analyst_name_entry = self.analyst_name_entry
        self.app.report_url_entry = self.report_url_entry
        self.app.upload_method = self.upload_method
        self.app.url_input_frame = self.url_input_frame
        self.app.url_input_textbox = self.url_input_textbox
        self.app.btn_new_case_upload = self.btn_upload
        self.app.new_case_status = self.status_label

        return self.frame

    def _load_logo(self, parent_frame: ctk.CTkFrame) -> bool:
        """Load and display the M.A.D. logo image"""
        try:
            # Try multiple possible locations for image.png
            possible_paths = [
                "image.png",
                os.path.join(os.getcwd(), "image.png"),
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "image.png"),
                os.path.join(os.path.expanduser("~"), "Desktop", "MAD", "image.png"),
                r"C:\Users\REM\Desktop\MAD\image.png"
            ]

            logo_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    logo_path = path
                    break

            if logo_path and os.path.exists(logo_path):
                # Load and resize image
                pil_image = Image.open(logo_path)

                # Keep aspect ratio, max size 300px
                max_size = 300
                pil_image.thumbnail((max_size, max_size), Image.Resampling.LANCZOS)

                logo_image = ctk.CTkImage(
                    light_image=pil_image,
                    dark_image=pil_image,
                    size=(pil_image.width, pil_image.height)
                )

                logo_label = ctk.CTkLabel(
                    parent_frame,
                    image=logo_image,
                    text=""
                )
                logo_label.image = logo_image  # Keep a reference
                logo_label.pack()
                return True

        except Exception as e:
            print(f"ERROR loading logo image: {e}")

        return False

    def _create_fallback_logo(self, parent_frame: ctk.CTkFrame):
        """Create fallback text-based logo if image.png is not found"""
        logo_shield = ctk.CTkLabel(
            parent_frame,
            text="🛡",
            font=Fonts.logo_emoji,
            text_color=self.colors["red"]
        )
        logo_shield.pack(side="left", padx=(0, 20))

        logo_text_frame = ctk.CTkFrame(parent_frame, fg_color="transparent")
        logo_text_frame.pack(side="left")

        logo_main = ctk.CTkLabel(
            logo_text_frame,
            text="M.A.D.",
            font=Fonts.logo_main,
            text_color="white"
        )
        logo_main.pack(anchor="w")

        logo_subtitle = ctk.CTkLabel(
            logo_text_frame,
            text="MALWARE ANALYSIS\nDASHBOARD",
            font=Fonts.logo_subtitle,
            text_color="white",
            justify="left"
        )
        logo_subtitle.pack(anchor="w")

    def _on_upload_method_change(self):
        """Handle upload method radio button change"""
        method = self.upload_method.get()
        if method == "url":
            self.url_input_frame.pack(pady=(10, 0), before=self.btn_upload)
            self.btn_upload.configure(text="Download and Start Case")
        else:
            self.url_input_frame.pack_forget()
            self.btn_upload.configure(text="Upload File to Start Case")

    def _handle_upload(self):
        """Handle file upload or URL download for new case"""
        method = self.upload_method.get()
        analyst_name = self.get_analyst_name()
        report_url = self.get_report_url()

        if method == "file":
            # Open file dialog to select files
            files = filedialog.askopenfilenames(
                title="Select files for analysis",
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

            # Generate case name from first file or prompt user
            default_name = os.path.splitext(os.path.basename(files[0]))[0] if files else "New_Case"
            case_name = simpledialog.askstring(
                "Case Name",
                "Enter a name for this case:",
                initialvalue=default_name,
                parent=self.app.root
            )

            if not case_name:
                return  # User cancelled

        elif method == "url":
            # Get URLs from text input
            urls = self.get_urls()
            if not urls:
                messagebox.showwarning("No URLs", "Please enter at least one URL to download")
                return

            # For URL downloads, use first URL as case name basis
            case_name = simpledialog.askstring(
                "Case Name",
                "Enter a name for this case:",
                initialvalue="URL_Download_Case",
                parent=self.app.root
            )

            if not case_name:
                return

            # TODO: Implement URL download logic
            # For now, show a message that URL download needs implementation
            messagebox.showinfo("Info", "URL download feature - files will be downloaded and processed")
            files = []  # Would be populated by download logic
            return  # Skip for now until URL download is implemented

        else:
            return

        # Show progress and delegate to app handler
        def progress_callback(current, total, filename):
            self.set_status(f"Processing {current}/{total}: {filename}")

        self.set_status("Starting case creation...")

        # Call app's handler with all parameters
        self.app.handle_new_case_upload(
            case_name=case_name,
            analyst_name=analyst_name,
            report_url=report_url,
            files=files,
            progress_callback=progress_callback
        )

    def get_analyst_name(self) -> str:
        """Get the analyst name from the form"""
        return self.analyst_name_entry.get().strip()

    def get_report_url(self) -> str:
        """Get the report URL from the form"""
        return self.report_url_entry.get().strip()

    def get_upload_method(self) -> str:
        """Get the selected upload method"""
        return self.upload_method.get()

    def get_urls(self) -> list:
        """Get URLs from the text input"""
        url_text = self.url_input_textbox.get("1.0", "end-1c").strip()
        return [url.strip() for url in url_text.split('\n') if url.strip()]

    def set_status(self, text: str):
        """Set the status label text"""
        self.status_label.configure(text=text)

    def clear_form(self):
        """Clear all form fields"""
        self.analyst_name_entry.delete(0, 'end')
        self.report_url_entry.delete(0, 'end')
        self.url_input_textbox.delete("1.0", "end")
        self.status_label.configure(text="")
