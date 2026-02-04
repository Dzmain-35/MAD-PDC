"""
Case Handlers
Business logic for case management operations.
"""

import os
import threading
from datetime import datetime
from tkinter import messagebox, filedialog
from typing import TYPE_CHECKING, Optional, Dict, Any, List, Callable

import customtkinter as ctk
import tkinter as tk

from typography import Fonts

if TYPE_CHECKING:
    from ui.app import ForensicAnalysisGUI


class CaseHandlers:
    """Handler class for case management business logic"""

    def __init__(self, app: 'ForensicAnalysisGUI'):
        self.app = app

    @property
    def case_manager(self):
        return self.app.case_manager

    @property
    def settings_manager(self):
        return self.app.settings_manager

    @property
    def current_case(self):
        return self.app.current_case

    @current_case.setter
    def current_case(self, value):
        self.app.current_case = value

    # ==================== CASE CREATION ====================
    def handle_new_case_upload(
            self,
            case_name: str,
            analyst_name: str,
            report_url: str,
            files: List[str],
            progress_callback: Optional[Callable] = None
    ) -> bool:
        """
        Handle new case upload with file scanning.

        Args:
            case_name: Name for the new case
            analyst_name: Name of the analyst
            report_url: URL for the associated report
            files: List of file paths to add to the case
            progress_callback: Optional callback for progress updates

        Returns:
            bool: True if case was created successfully
        """
        if not case_name:
            messagebox.showwarning("Missing Info", "Please enter a case name")
            return False

        if not files:
            messagebox.showwarning("No Files", "Please select at least one file")
            return False

        # Check for scan in progress
        if self.app.scan_in_progress:
            messagebox.showwarning("Scan In Progress", "A scan is already running. Please wait.")
            return False

        self.app.scan_in_progress = True

        def process_case():
            try:
                # Create case directory
                case_dir = self.case_manager.create_case_directory(case_name)

                # Initialize case data
                case_data = {
                    "id": os.path.basename(case_dir),
                    "name": case_name,
                    "analyst_name": analyst_name,
                    "report_url": report_url,
                    "created": datetime.now().isoformat(),
                    "files": [],
                    "total_threats": 0,
                    "total_vt_hits": 0,
                    "files_with_yara": 0,
                    "files_with_thq": 0,
                    "files_with_vt": 0,
                    "iocs": {"urls": [], "ips": [], "domains": []},
                    "notes": ""
                }

                # Process files
                for i, file_path in enumerate(files):
                    if progress_callback:
                        self.app.root.after(0, lambda idx=i, fp=file_path: progress_callback(
                            idx + 1, len(files), os.path.basename(fp)
                        ))

                    # Process file and get results
                    file_info = self.case_manager.process_case_file(file_path, case_dir)

                    if file_info:
                        case_data["files"].append(file_info)

                        # Update statistics
                        has_yara = bool(file_info.get("yara_matches"))
                        has_thq = file_info.get("thq_family") not in [None, "", "Unknown", "N/A"]
                        has_vt = file_info.get("vt_hits", 0) > 0

                        if has_yara:
                            case_data["files_with_yara"] += 1
                        if has_thq:
                            case_data["files_with_thq"] += 1
                        if has_vt:
                            case_data["files_with_vt"] += 1
                        if has_yara or has_thq or has_vt:
                            case_data["total_threats"] += 1
                        case_data["total_vt_hits"] += file_info.get("vt_hits", 0)

                # Save case metadata
                self.case_manager.save_case_metadata(case_dir, case_data)

                # Update app state
                self.current_case = case_data

                # Update UI
                self.app.root.after(0, self.app.close_progress_window)
                self.app.root.after(0, self.app.update_current_case_display)
                self.app.root.after(0, lambda: self.app.switch_tab("current_case"))
                self.app.root.after(0, lambda: messagebox.showinfo(
                    "Success",
                    f"Case '{case_name}' created successfully!\n\n"
                    f"Files processed: {len(case_data['files'])}\n"
                    f"Threats detected: {case_data['total_threats']}"
                ))

            except Exception as e:
                self.app.root.after(0, self.app.close_progress_window)
                self.app.root.after(0, lambda: messagebox.showerror("Error", f"Failed to create case: {str(e)}"))
                import traceback
                traceback.print_exc()

            finally:
                self.app.scan_in_progress = False

        thread = threading.Thread(target=process_case, daemon=True)
        thread.start()
        return True

    # ==================== ADD FILES TO CASE ====================
    def handle_add_files(
            self,
            files: List[str],
            progress_callback: Optional[Callable] = None
    ) -> bool:
        """
        Add files to existing case.

        Args:
            files: List of file paths to add
            progress_callback: Optional callback for progress updates

        Returns:
            bool: True if files were added successfully
        """
        if not self.current_case:
            messagebox.showwarning("No Case", "No active case. Please create a new case first.")
            return False

        if not files:
            messagebox.showwarning("No Files", "Please select files to add")
            return False

        if self.app.scan_in_progress:
            messagebox.showwarning("Scan In Progress", "A scan is already running. Please wait.")
            return False

        self.app.scan_in_progress = True

        def add_files_thread():
            try:
                case_dir = os.path.join(self.case_manager.case_storage_path, self.current_case["id"])

                for i, file_path in enumerate(files):
                    if progress_callback:
                        self.app.root.after(0, lambda idx=i, fp=file_path: progress_callback(
                            idx + 1, len(files), os.path.basename(fp)
                        ))

                    file_info = self.case_manager.process_case_file(file_path, case_dir)

                    if file_info:
                        self.current_case["files"].append(file_info)

                        # Update statistics
                        has_yara = bool(file_info.get("yara_matches"))
                        has_thq = file_info.get("thq_family") not in [None, "", "Unknown", "N/A"]
                        has_vt = file_info.get("vt_hits", 0) > 0

                        if has_yara:
                            self.current_case["files_with_yara"] = self.current_case.get("files_with_yara", 0) + 1
                        if has_thq:
                            self.current_case["files_with_thq"] = self.current_case.get("files_with_thq", 0) + 1
                        if has_vt:
                            self.current_case["files_with_vt"] = self.current_case.get("files_with_vt", 0) + 1
                        if has_yara or has_thq or has_vt:
                            self.current_case["total_threats"] += 1
                        self.current_case["total_vt_hits"] += file_info.get("vt_hits", 0)

                # Save updated metadata
                self.case_manager.save_case_metadata(case_dir, self.current_case)

                # Update UI
                self.app.root.after(0, self.app.close_progress_window)
                self.app.root.after(0, self.app.update_current_case_display)
                self.app.root.after(0, lambda: messagebox.showinfo(
                    "Success",
                    f"Added {len(files)} files to case\n"
                    f"Total files: {len(self.current_case['files'])}\n"
                    f"Total threats: {self.current_case['total_threats']}"
                ))

            except Exception as e:
                self.app.root.after(0, self.app.close_progress_window)
                self.app.root.after(0, lambda: messagebox.showerror("Error", f"Failed to add files: {str(e)}"))
                import traceback
                traceback.print_exc()

            finally:
                self.app.scan_in_progress = False

        thread = threading.Thread(target=add_files_thread, daemon=True)
        thread.start()
        return True

    # ==================== IOC MANAGEMENT ====================
    def show_add_ioc_dialog(self):
        """Show dialog to add IOC to current case"""
        if not self.current_case:
            messagebox.showwarning("No Case", "No active case to add IOC to")
            return

        dialog = ctk.CTkToplevel(self.app.root)
        dialog.title("Add IOC")
        dialog.geometry("500x300")
        dialog.transient(self.app.root)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (dialog.winfo_screenheight() // 2) - (300 // 2)
        dialog.geometry(f"500x300+{x}+{y}")

        # Content frame
        content = ctk.CTkFrame(dialog, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=20, pady=20)

        # Title
        title_label = ctk.CTkLabel(
            content, text="Add Indicator of Compromise",
            font=Fonts.title_medium
        )
        title_label.pack(pady=(0, 15))

        # IOC Type selection
        type_label = ctk.CTkLabel(
            content, text="IOC Type:",
            font=Fonts.body_bold, anchor="w"
        )
        type_label.pack(anchor="w", pady=(0, 5))

        ioc_type_var = tk.StringVar(value="urls")
        type_frame = ctk.CTkFrame(content, fg_color="transparent")
        type_frame.pack(anchor="w", pady=(0, 10))

        colors = self.app.colors
        ctk.CTkRadioButton(
            type_frame, text="URL", variable=ioc_type_var, value="urls",
            fg_color=colors["red"]
        ).pack(side="left", padx=(0, 10))
        ctk.CTkRadioButton(
            type_frame, text="IP Address", variable=ioc_type_var, value="ips",
            fg_color=colors["red"]
        ).pack(side="left", padx=(0, 10))
        ctk.CTkRadioButton(
            type_frame, text="Domain", variable=ioc_type_var, value="domains",
            fg_color=colors["red"]
        ).pack(side="left")

        # IOC Value input
        value_label = ctk.CTkLabel(
            content, text="IOC Value:",
            font=Fonts.body_bold, anchor="w"
        )
        value_label.pack(anchor="w", pady=(0, 5))

        ioc_value_entry = ctk.CTkEntry(content, width=450, height=35)
        ioc_value_entry.pack(pady=(0, 20))
        ioc_value_entry.focus()

        # Buttons
        btn_frame = ctk.CTkFrame(content, fg_color="transparent")
        btn_frame.pack(pady=(10, 0))

        def add_ioc():
            ioc_type = ioc_type_var.get()
            ioc_value = ioc_value_entry.get().strip()

            if not ioc_value:
                messagebox.showwarning("Empty Value", "Please enter an IOC value")
                return

            self.case_manager.add_ioc(ioc_type, ioc_value)
            self.app.refresh_iocs_display()
            messagebox.showinfo("Success", f"IOC added successfully!\n\nType: {ioc_type}\nValue: {ioc_value}")
            dialog.destroy()

        btn_add = ctk.CTkButton(
            btn_frame, text="Add IOC", command=add_ioc,
            width=120, height=35,
            fg_color=colors["red"], hover_color=colors["red_dark"]
        )
        btn_add.pack(side="left", padx=5)

        btn_cancel = ctk.CTkButton(
            btn_frame, text="Cancel", command=dialog.destroy,
            width=120, height=35,
            fg_color="gray40", hover_color="gray30"
        )
        btn_cancel.pack(side="left", padx=5)

    def refresh_iocs_display(self):
        """Refresh the IOCs display in the Current Case tab"""
        if not self.current_case:
            return

        iocs = self.current_case.get("iocs", {"urls": [], "ips": [], "domains": []})

        # Clear existing content
        self.app.iocs_urls_list.delete("1.0", "end")
        self.app.iocs_ips_list.delete("1.0", "end")
        self.app.iocs_domains_list.delete("1.0", "end")

        # Display IOCs
        if iocs.get("urls"):
            self.app.iocs_urls_list.insert("1.0", "\n".join(iocs["urls"]))
        else:
            self.app.iocs_urls_list.insert("1.0", "No URLs recorded")

        if iocs.get("ips"):
            self.app.iocs_ips_list.insert("1.0", "\n".join(iocs["ips"]))
        else:
            self.app.iocs_ips_list.insert("1.0", "No IP addresses recorded")

        if iocs.get("domains"):
            self.app.iocs_domains_list.insert("1.0", "\n".join(iocs["domains"]))
        else:
            self.app.iocs_domains_list.insert("1.0", "No domains recorded")

    # ==================== NOTES MANAGEMENT ====================
    def handle_save_notes(self):
        """Save notes to the current case"""
        if not self.current_case:
            messagebox.showwarning("No Case", "No active case to save notes to")
            return

        notes = self.app.notes_textbox.get("1.0", "end-1c").strip()

        if not notes:
            messagebox.showwarning("Empty Notes", "Please enter some notes before saving")
            return

        try:
            self.current_case["notes"] = notes
            case_dir = os.path.join(self.case_manager.case_storage_path, self.current_case["id"])

            # Save updated case metadata
            self.case_manager.save_case_metadata(case_dir, self.current_case)

            # Also save notes as a separate text file
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

    # ==================== FILE DELETION ====================
    def delete_file_from_case(self, file_info: Dict[str, Any], card_frame) -> bool:
        """
        Delete a file from the current case.

        Args:
            file_info: Dictionary containing file information
            card_frame: The GUI frame/card to remove

        Returns:
            bool: True if deletion was successful
        """
        try:
            file_path = file_info.get('storage_path', '')
            file_name = file_info['filename']

            # Remove file from disk
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
                print(f"Deleted file: {file_path}")

                # Also remove associated files
                for suffix in ['_details.json', '_decoded.txt']:
                    associated_path = file_path + suffix
                    if os.path.exists(associated_path):
                        os.remove(associated_path)

            # Remove from current case files list
            if file_info in self.current_case["files"]:
                self.current_case["files"].remove(file_info)

            # Update case statistics
            if not file_info.get("whitelisted", False):
                yara_matches = file_info.get("yara_matches", [])
                if yara_matches:
                    self.current_case["files_with_yara"] = max(0, self.current_case.get("files_with_yara", 0) - 1)

                thq_family = file_info.get("thq_family", "")
                if thq_family and thq_family not in ["Unknown", "N/A"]:
                    self.current_case["files_with_thq"] = max(0, self.current_case.get("files_with_thq", 0) - 1)

                vt_hits = file_info.get("vt_hits", 0)
                if vt_hits > 0:
                    self.current_case["files_with_vt"] = max(0, self.current_case.get("files_with_vt", 0) - 1)
                    self.current_case["total_vt_hits"] = max(0, self.current_case.get("total_vt_hits", 0) - vt_hits)

            # Save updated case metadata
            if self.current_case and self.current_case.get("id"):
                case_dir = os.path.join(self.case_manager.case_storage_path, self.current_case["id"])
                self.case_manager.save_case_metadata(case_dir, self.current_case)

            # Remove the card from display
            card_frame.destroy()

            # Update stats display
            self.app.update_current_case_display()

            messagebox.showinfo("File Deleted", f"Successfully deleted {file_name} from the case.")
            return True

        except Exception as e:
            messagebox.showerror("Delete Error", f"Failed to delete file:\n\n{str(e)}")
            print(f"Error deleting file: {e}")
            return False

    # ==================== CASE EXPORT ====================
    def export_case(self, export_format: str = "json") -> bool:
        """
        Export current case to file.

        Args:
            export_format: Export format ("json" or "csv")

        Returns:
            bool: True if export was successful
        """
        if not self.current_case:
            messagebox.showwarning("No Case", "No active case to export")
            return False

        default_name = f"{self.current_case['name']}_export"
        if export_format == "json":
            filetypes = [("JSON files", "*.json"), ("All files", "*.*")]
            default_name += ".json"
        else:
            filetypes = [("CSV files", "*.csv"), ("All files", "*.*")]
            default_name += ".csv"

        file_path = filedialog.asksaveasfilename(
            title="Export Case",
            defaultextension=f".{export_format}",
            initialfile=default_name,
            filetypes=filetypes
        )

        if not file_path:
            return False

        try:
            include_metadata = self.settings_manager.get("export.include_metadata", True)
            include_hashes = self.settings_manager.get("export.include_hashes", True)

            success = self.case_manager.export_case(
                self.current_case,
                file_path,
                format=export_format,
                include_metadata=include_metadata,
                include_hashes=include_hashes
            )

            if success:
                messagebox.showinfo("Export Complete", f"Case exported to:\n{file_path}")
                return True
            else:
                messagebox.showerror("Export Failed", "Failed to export case")
                return False

        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting case:\n{str(e)}")
            return False
