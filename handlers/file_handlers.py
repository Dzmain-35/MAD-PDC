"""
File Handlers
Business logic for file viewing, string extraction, and execution operations.
"""

import os
import threading
from tkinter import messagebox, filedialog, ttk
from typing import TYPE_CHECKING, Optional, Dict, Any, List, Callable

import customtkinter as ctk
import tkinter as tk

from typography import Fonts

if TYPE_CHECKING:
    from ui.app import ForensicAnalysisGUI


class FileHandlers:
    """Handler class for file viewing and analysis business logic"""

    def __init__(self, app: 'ForensicAnalysisGUI'):
        self.app = app

    @property
    def colors(self):
        return self.app.colors

    @property
    def process_monitor(self):
        return self.app.process_monitor

    # ==================== FILE STRINGS VIEWER ====================
    def view_file_strings(self, file_path: str, file_name: str):
        """View extracted strings from a static file in a dedicated window"""
        # Create window
        strings_window = ctk.CTkToplevel(self.app.root)
        strings_window.title(f"File Strings: {file_name}")
        strings_window.geometry("1000x700")

        # Main container
        main_container = ctk.CTkFrame(strings_window, fg_color=self.colors["dark_blue"])
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Header
        header = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=60)
        header.pack(fill="x", padx=0, pady=(0, 10))
        header.pack_propagate(False)

        title = ctk.CTkLabel(header, text=f"{file_name}", font=Fonts.logo_subtitle)
        title.pack(side="left", padx=20, pady=15)

        # Search and filter controls
        search_frame = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=90)
        search_frame.pack(fill="x", padx=10, pady=10)
        search_frame.pack_propagate(False)

        # First row: Search
        search_row = ctk.CTkFrame(search_frame, fg_color="transparent")
        search_row.pack(fill="x", padx=5, pady=(5, 0))

        search_label = ctk.CTkLabel(search_row, text="Search:", font=Fonts.body_bold)
        search_label.pack(side="left", padx=(10, 5))

        search_entry = ctk.CTkEntry(
            search_row, width=300, height=35,
            placeholder_text="Enter search term...", font=Fonts.body
        )
        search_entry.pack(side="left", padx=5)

        status_label = ctk.CTkLabel(
            search_row, text="Extracting strings...",
            font=Fonts.helper, text_color="gray60"
        )
        status_label.pack(side="left", padx=20)

        # Second row: Filters
        filter_row = ctk.CTkFrame(search_frame, fg_color="transparent")
        filter_row.pack(fill="x", padx=5, pady=(5, 5))

        length_label = ctk.CTkLabel(filter_row, text="Length:", font=Fonts.body_bold)
        length_label.pack(side="left", padx=(10, 5))

        min_label = ctk.CTkLabel(filter_row, text="Min:", font=Fonts.helper)
        min_label.pack(side="left", padx=(5, 2))

        min_length_entry = ctk.CTkEntry(filter_row, width=60, height=30, placeholder_text="4", font=Fonts.helper)
        min_length_entry.insert(0, "4")
        min_length_entry.pack(side="left", padx=2)

        max_label = ctk.CTkLabel(filter_row, text="Max:", font=Fonts.helper)
        max_label.pack(side="left", padx=(10, 2))

        max_length_entry = ctk.CTkEntry(filter_row, width=60, height=30, placeholder_text="inf", font=Fonts.helper)
        max_length_entry.pack(side="left", padx=2)

        # Quality filter toggle
        quality_filter_var = ctk.BooleanVar(value=True)
        quality_filter_checkbox = ctk.CTkCheckBox(
            filter_row, text="Quality Filter", variable=quality_filter_var,
            font=Fonts.helper, checkbox_width=20, checkbox_height=20
        )
        quality_filter_checkbox.pack(side="left", padx=15)

        # Export button
        export_btn = ctk.CTkButton(
            filter_row, text="Export TXT", command=lambda: None,
            height=30, width=120,
            fg_color=self.colors["red"], hover_color=self.colors["red_dark"],
            font=Fonts.label
        )
        export_btn.pack(side="left", padx=5)

        # Strings text area
        strings_text_frame = ctk.CTkFrame(main_container, fg_color="gray20")
        strings_text_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        vsb = tk.Scrollbar(strings_text_frame, orient="vertical", bg="#1a1a1a")
        vsb.pack(side="right", fill="y")

        hsb = tk.Scrollbar(strings_text_frame, orient="horizontal", bg="#1a1a1a")
        hsb.pack(side="bottom", fill="x")

        strings_text = tk.Text(
            strings_text_frame, wrap="none", bg="#1a1a1a", fg="#ffffff",
            font=Fonts.monospace(10),
            yscrollcommand=vsb.set, xscrollcommand=hsb.set
        )
        strings_text.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        vsb.config(command=strings_text.yview)
        hsb.config(command=strings_text.xview)

        # Store extraction data
        extraction_data = {"strings": [], "extraction_result": None}

        def search_strings(event=None):
            """Search and filter strings"""
            search_term = search_entry.get().strip().lower()

            try:
                min_len = int(min_length_entry.get()) if min_length_entry.get() else 0
            except ValueError:
                min_len = 0

            try:
                max_len = int(max_length_entry.get()) if max_length_entry.get() else float('inf')
            except ValueError:
                max_len = float('inf')

            strings_text.configure(state="normal")
            strings_text.delete("1.0", "end")

            length_filtered = [s for s in extraction_data["strings"] if min_len <= len(s) <= max_len]

            if not search_term:
                if length_filtered:
                    display_text = "\n".join(length_filtered[:5000])
                    strings_text.insert("1.0", display_text)
                    filter_msg = ""
                    if min_len > 0 or max_len < float('inf'):
                        filter_msg = f" (filtered: {min_len}-{max_len if max_len != float('inf') else 'inf'})"
                    status_label.configure(text=f"Showing: {len(length_filtered)} strings{filter_msg}")
                else:
                    strings_text.insert("1.0", "No strings match the filters")
                    status_label.configure(text="No matches")
            else:
                filtered = [s for s in length_filtered if search_term in s.lower()]

                if filtered:
                    for s in filtered[:5000]:
                        strings_text.insert("end", s + "\n")
                    filter_msg = ""
                    if min_len > 0 or max_len < float('inf'):
                        filter_msg = f" (length: {min_len}-{max_len if max_len != float('inf') else 'inf'})"
                    status_label.configure(text=f"Found: {len(filtered)} matches{filter_msg}")
                else:
                    strings_text.insert("1.0", f"No strings found matching '{search_term}'")
                    status_label.configure(text="No matches")

            strings_text.configure(state="disabled")

        search_entry.bind("<KeyRelease>", search_strings)
        min_length_entry.bind("<KeyRelease>", search_strings)
        max_length_entry.bind("<KeyRelease>", search_strings)

        def extract_file_strings():
            """Extract strings from file in background"""
            try:
                status_label.configure(text="Extracting strings from file...")
                export_btn.configure(state="disabled")

                # Import file string extractor
                import sys
                sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'analysis_modules'))
                from file_string_extractor import FileStringExtractor

                extractor = FileStringExtractor(verbose=True)
                use_quality_filter = quality_filter_var.get()

                def progress_callback(bytes_processed, total_bytes, current_strings):
                    pct = (bytes_processed / total_bytes * 100) if total_bytes > 0 else 0
                    self.app.root.after(0, lambda: status_label.configure(
                        text=f"Extracting: {pct:.0f}% ({current_strings} strings so far...)"
                    ))

                result = extractor.extract_strings_from_file(
                    file_path,
                    min_length=4,
                    max_strings=50000,
                    include_unicode=True,
                    enable_quality_filter=use_quality_filter,
                    progress_callback=progress_callback,
                    scan_mode="quick"
                )

                all_strings = []
                for category, strings in result['strings'].items():
                    all_strings.extend(strings)

                extraction_data["strings"] = all_strings
                extraction_data["extraction_result"] = result

                self.app.root.after(0, lambda: status_label.configure(
                    text=f"Complete: {len(all_strings)} strings extracted in {result.get('extraction_time', 0):.2f}s"
                ))
                self.app.root.after(0, lambda: export_btn.configure(state="normal"))
                self.app.root.after(0, search_strings)

            except Exception as e:
                import traceback
                traceback.print_exc()
                self.app.root.after(0, lambda: status_label.configure(text=f"Error: {str(e)}"))
                self.app.root.after(0, lambda: strings_text.configure(state="normal"))
                self.app.root.after(0, lambda: strings_text.delete("1.0", "end"))
                self.app.root.after(0, lambda: strings_text.insert("1.0", f"Error extracting strings:\n{str(e)}"))
                self.app.root.after(0, lambda: strings_text.configure(state="disabled"))
                self.app.root.after(0, lambda: export_btn.configure(state="normal"))

        def export_file_strings():
            """Export strings to TXT file"""
            try:
                if not extraction_data["extraction_result"]:
                    messagebox.showwarning("No Data", "No strings available to export")
                    return

                default_name = f"{os.path.splitext(file_name)[0]}_strings.txt"
                save_path = filedialog.asksaveasfilename(
                    title="Export Strings",
                    defaultextension=".txt",
                    initialfile=default_name,
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
                )

                if not save_path:
                    return

                import sys
                sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'analysis_modules'))
                from file_string_extractor import FileStringExtractor

                extractor = FileStringExtractor()
                success = extractor.export_to_txt(
                    extraction_data["extraction_result"],
                    save_path,
                    include_metadata=True
                )

                if success:
                    messagebox.showinfo("Export Complete", f"Strings exported to:\n{save_path}")
                else:
                    messagebox.showerror("Export Failed", "Failed to export strings")

            except Exception as e:
                messagebox.showerror("Export Error", f"Error exporting:\n{str(e)}")
                import traceback
                traceback.print_exc()

        export_btn.configure(command=export_file_strings)
        quality_filter_checkbox.configure(
            command=lambda: threading.Thread(target=extract_file_strings, daemon=True).start()
        )

        # Start initial extraction
        threading.Thread(target=extract_file_strings, daemon=True).start()

    # ==================== HEX VIEWER ====================
    def view_file_hex(self, file_path: str, file_name: str):
        """View file in hex format"""
        from analysis_modules.file_viewer_executor import get_viewer_executor
        viewer = get_viewer_executor()

        hex_window = ctk.CTkToplevel(self.app.root)
        hex_window.title(f"Hex View: {file_name}")
        hex_window.geometry("1200x700")

        main_container = ctk.CTkFrame(hex_window, fg_color=self.colors["dark_blue"])
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Header
        header = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=60)
        header.pack(fill="x", padx=0, pady=(0, 10))
        header.pack_propagate(False)

        title = ctk.CTkLabel(header, text=f"Hex View: {file_name}", font=Fonts.logo_subtitle)
        title.pack(side="left", padx=20, pady=15)

        file_info = viewer.get_file_info(file_path)
        info_text = f"Size: {file_info.get('size_kb', 0):.2f} KB"
        info_label = ctk.CTkLabel(header, text=info_text, font=Fonts.helper, text_color="gray60")
        info_label.pack(side="right", padx=20)

        # Text display
        text_frame = ctk.CTkFrame(main_container, fg_color=self.colors["navy"])
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        hex_text = tk.Text(
            text_frame, wrap="none", bg="#0d1520", fg="#ffffff",
            font=("Courier New", 10),
            selectbackground="#2a4d6e", selectforeground="#ffffff"
        )

        vsb = ttk.Scrollbar(text_frame, orient="vertical", command=hex_text.yview)
        hsb = ttk.Scrollbar(text_frame, orient="horizontal", command=hex_text.xview)
        hex_text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        hex_text.pack(side="left", fill="both", expand=True)

        def load_hex():
            hex_content, bytes_read = viewer.read_file_as_hex(file_path, max_bytes=1024*1024)
            hex_text.delete("1.0", "end")
            hex_text.insert("1.0", hex_content)
            hex_text.configure(state="disabled")

            if bytes_read >= 1024*1024:
                hex_text.insert("end", f"\n\n... (showing first 1MB of {file_info.get('size_mb', 0):.2f} MB)")

        threading.Thread(target=load_hex, daemon=True).start()

    # ==================== TEXT VIEWER ====================
    def view_file_text(self, file_path: str, file_name: str):
        """View file as text"""
        from analysis_modules.file_viewer_executor import get_viewer_executor
        viewer = get_viewer_executor()

        text_window = ctk.CTkToplevel(self.app.root)
        text_window.title(f"Text View: {file_name}")
        text_window.geometry("1200x700")

        main_container = ctk.CTkFrame(text_window, fg_color=self.colors["dark_blue"])
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Header
        header = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=60)
        header.pack(fill="x", padx=0, pady=(0, 10))
        header.pack_propagate(False)

        title = ctk.CTkLabel(header, text=f"Text View: {file_name}", font=Fonts.logo_subtitle)
        title.pack(side="left", padx=20, pady=15)

        file_info = viewer.get_file_info(file_path)
        info_text = f"Size: {file_info.get('size_kb', 0):.2f} KB"
        info_label = ctk.CTkLabel(header, text=info_text, font=Fonts.helper, text_color="gray60")
        info_label.pack(side="right", padx=20)

        # Text display
        text_frame = ctk.CTkFrame(main_container, fg_color=self.colors["navy"])
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        file_text = tk.Text(
            text_frame, wrap="word", bg="#0d1520", fg="#ffffff",
            font=("Courier New", 10),
            selectbackground="#2a4d6e", selectforeground="#ffffff"
        )

        vsb = ttk.Scrollbar(text_frame, orient="vertical", command=file_text.yview)
        hsb = ttk.Scrollbar(text_frame, orient="horizontal", command=file_text.xview)
        file_text.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        file_text.pack(side="left", fill="both", expand=True)

        def load_text():
            text_content = viewer.read_file_as_text(file_path, max_bytes=1024*1024)
            file_text.delete("1.0", "end")
            file_text.insert("1.0", text_content)
            file_text.configure(state="disabled")

        threading.Thread(target=load_text, daemon=True).start()

    # ==================== FILE EXECUTION ====================
    def execute_file(self, file_path: str, file_name: str, suspended: bool = False):
        """Execute a file with optional suspended start"""
        from analysis_modules.file_viewer_executor import get_viewer_executor
        viewer = get_viewer_executor()

        if suspended:
            # Warn user about suspended execution
            if not messagebox.askyesno(
                "Confirm Suspended Execution",
                f"This will start the file in a SUSPENDED state.\n\n"
                f"File: {file_name}\n\n"
                f"The process will be paused immediately after creation. "
                f"You can resume it from the Process Monitor.\n\n"
                f"Continue?"
            ):
                return

            success, result = viewer.execute_file_suspended(file_path)
            if success:
                pid = result.get('pid', 'Unknown')
                messagebox.showinfo(
                    "Suspended Execution",
                    f"Process started in SUSPENDED state.\n\n"
                    f"PID: {pid}\n"
                    f"File: {file_name}\n\n"
                    f"Use Process Monitor to resume or analyze."
                )

                # Focus on the new process in process tree
                if pid and pid != 'Unknown':
                    self.app.process_handlers.focus_process_by_pid(int(pid))
            else:
                messagebox.showerror(
                    "Execution Failed",
                    f"Failed to start suspended process.\n\nError: {result.get('error', 'Unknown error')}"
                )
        else:
            # Normal execution - warn user
            if not messagebox.askyesno(
                "Confirm Execution",
                f"WARNING: You are about to execute a potentially malicious file!\n\n"
                f"File: {file_name}\n\n"
                f"This should only be done in a controlled analysis environment.\n\n"
                f"Continue?"
            ):
                return

            success, result = viewer.execute_file(file_path)
            if success:
                pid = result.get('pid', 'Unknown')
                messagebox.showinfo(
                    "File Executed",
                    f"Process started successfully.\n\n"
                    f"PID: {pid}\n"
                    f"File: {file_name}"
                )

                # Focus on the new process
                if pid and pid != 'Unknown':
                    self.app.process_handlers.focus_process_by_pid(int(pid))
            else:
                messagebox.showerror(
                    "Execution Failed",
                    f"Failed to execute file.\n\nError: {result.get('error', 'Unknown error')}"
                )

    # ==================== PROCESS STRINGS VIEWER ====================
    def view_process_strings(self, pid: int, process_name: str):
        """View extracted strings from a running process"""
        strings_window = ctk.CTkToplevel(self.app.root)
        strings_window.title(f"Process Strings: {process_name} (PID {pid})")
        strings_window.geometry("1000x700")

        main_container = ctk.CTkFrame(strings_window, fg_color=self.colors["dark_blue"])
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Header
        header = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=60)
        header.pack(fill="x", padx=0, pady=(0, 10))
        header.pack_propagate(False)

        title = ctk.CTkLabel(header, text=f"{process_name} (PID {pid})", font=Fonts.logo_subtitle)
        title.pack(side="left", padx=20, pady=15)

        # Controls
        controls_frame = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=60)
        controls_frame.pack(fill="x", padx=10, pady=10)
        controls_frame.pack_propagate(False)

        search_entry = ctk.CTkEntry(
            controls_frame, width=300, height=35,
            placeholder_text="Search strings...", font=Fonts.body
        )
        search_entry.pack(side="left", padx=10, pady=10)

        status_label = ctk.CTkLabel(
            controls_frame, text="Extracting strings...",
            font=Fonts.helper, text_color="gray60"
        )
        status_label.pack(side="left", padx=20)

        quick_scan_btn = ctk.CTkButton(
            controls_frame, text="Quick Scan", height=30, width=100,
            fg_color=self.colors["red"], hover_color=self.colors["red_dark"]
        )
        quick_scan_btn.pack(side="right", padx=5, pady=10)

        deep_scan_btn = ctk.CTkButton(
            controls_frame, text="Deep Scan", height=30, width=100,
            fg_color="transparent", border_width=2, border_color=self.colors["red"]
        )
        deep_scan_btn.pack(side="right", padx=5, pady=10)

        # Text area
        text_frame = ctk.CTkFrame(main_container, fg_color="gray20")
        text_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        vsb = tk.Scrollbar(text_frame, orient="vertical", bg="#1a1a1a")
        vsb.pack(side="right", fill="y")

        strings_text = tk.Text(
            text_frame, wrap="none", bg="#1a1a1a", fg="#ffffff",
            font=Fonts.monospace(10), yscrollcommand=vsb.set
        )
        strings_text.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        vsb.config(command=strings_text.yview)

        all_strings_data = {"strings": [], "current_mode": "quick"}

        def extract(scan_mode="quick"):
            try:
                all_strings_data["current_mode"] = scan_mode
                status_label.configure(text=f"Extracting strings ({scan_mode} mode)...")

                result = self.process_monitor.extract_strings_from_process(
                    pid,
                    min_length=4,
                    limit=20000,
                    enable_quality_filter=True,
                    scan_mode=scan_mode,
                    return_full_result=True
                )

                strings = result.get('strings', [])
                all_strings_data["strings"] = strings

                self.app.root.after(0, lambda: strings_text.configure(state="normal"))
                self.app.root.after(0, lambda: strings_text.delete("1.0", "end"))
                self.app.root.after(0, lambda: strings_text.insert("1.0", "\n".join(strings[:5000])))
                self.app.root.after(0, lambda: strings_text.configure(state="disabled"))
                self.app.root.after(0, lambda: status_label.configure(
                    text=f"Complete: {len(strings)} strings ({scan_mode} mode)"
                ))

            except Exception as e:
                self.app.root.after(0, lambda: status_label.configure(text=f"Error: {str(e)}"))

        def search_strings(event=None):
            search_term = search_entry.get().strip().lower()
            strings_text.configure(state="normal")
            strings_text.delete("1.0", "end")

            if not search_term:
                strings_text.insert("1.0", "\n".join(all_strings_data["strings"][:5000]))
            else:
                filtered = [s for s in all_strings_data["strings"] if search_term in s.lower()]
                strings_text.insert("1.0", "\n".join(filtered[:5000]))
                status_label.configure(text=f"Found: {len(filtered)} matches")

            strings_text.configure(state="disabled")

        search_entry.bind("<KeyRelease>", search_strings)
        quick_scan_btn.configure(command=lambda: threading.Thread(target=lambda: extract("quick"), daemon=True).start())
        deep_scan_btn.configure(command=lambda: threading.Thread(target=lambda: extract("deep"), daemon=True).start())

        # Start initial extraction
        threading.Thread(target=lambda: extract("quick"), daemon=True).start()
