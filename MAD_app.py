"""
MAD - Malware Analysis Dashboard
Thin application shell that coordinates views and manages shared state.

This file was refactored from the original 8660-line MAD.py monolith.
View-specific UI and logic now live in the views/ package.
"""

import customtkinter as ctk
from tkinter import filedialog, messagebox
from datetime import datetime
from case_manager import CaseManager
import os
import socket
import threading
import subprocess
import shutil
import platform
import webbrowser
from analysis_modules.process_monitor import ProcessMonitor
from analysis_modules.persistence_monitor import PersistenceMonitor
from analysis_modules.http_monitor import HttpTrafficMonitor
from analysis_modules.procmon_events import ProcmonLiveMonitor, ProcmonEvent
from analysis_modules.system_wide_monitor import SystemWideMonitor, EventFilter
from analysis_modules.sysmon_parser import SysmonLogMonitor
from analysis_modules.file_viewer_executor import get_viewer_executor
import tkinter as tk
from tkinter import ttk
import re
from typography import Fonts
from yara_rule_manager import YaraRuleManager
from sigma_rule_manager import SigmaRuleManager
from analysis_modules.sigma_evaluator import SigmaEvaluator
from settings_manager import SettingsManager

from views.event_bus import EventBus
from views.new_case_view import NewCaseView
from views.settings_view import SettingsView
from views.yara_rules_view import YaraRulesView
from views.current_case_view import CurrentCaseView
from views.process_view import ProcessView
from views.live_events_view import LiveEventsView


class ForensicAnalysisGUI:
    def __init__(self):
        # Configure appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Initialize main window
        self.root = ctk.CTk()
        self.root.title("MAD - Malware Analysis Dashboard")

        # Detect screen size and set responsive geometry
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()

        win_w = max(1000, min(int(screen_w * 0.80), 2400))
        win_h = max(700, min(int(screen_h * 0.80), 1600))
        x_pos = (screen_w - win_w) // 2
        y_pos = (screen_h - win_h) // 2
        self.root.geometry(f"{win_w}x{win_h}+{x_pos}+{y_pos}")
        self.root.minsize(1000, 700)

        # Screen metrics
        self.screen_width = screen_w
        self.screen_height = screen_h
        self._is_large_screen = screen_w >= 1920
        self._sidebar_width = 220 if self._is_large_screen else 160

        # Color scheme
        self.colors = {
            "dark_blue": "#1a2332",
            "navy": "#0d1520",
            "red": "#dc2626",
            "red_dark": "#991b1b",
            "sidebar_bg": "#991b1b"
        }

        # Event bus for cross-view communication
        self.event_bus = EventBus()

        # Initialize settings manager
        self.settings_manager = SettingsManager()
        print("Settings loaded successfully")

        # Get API keys from settings
        vt_api_key = self.settings_manager.get("api_keys.virustotal")
        threathq_user = self.settings_manager.get("api_keys.threathq_user")
        threathq_pass = self.settings_manager.get("api_keys.threathq_pass")

        # Initialize case manager
        self.case_manager = CaseManager(
            vt_api_key=vt_api_key if vt_api_key else None,
            threathq_user=threathq_user if threathq_user else None,
            threathq_pass=threathq_pass if threathq_pass else None,
            settings_manager=self.settings_manager
        )
        print(f"Case storage initialized at: {self.case_manager.case_storage_path}")

        # Initialize YARA rule manager
        self.yara_rule_manager = YaraRuleManager(
            self.case_manager.yara_rules_path,
            settings_manager=self.settings_manager
        )

        # Initialize Sigma rule manager
        self.sigma_rules_path = self.settings_manager.get("sigma.sigma_rules_path", "")
        if not self.sigma_rules_path:
            self.sigma_rules_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "sigma_rules"
            )
        self.sigma_rule_manager = SigmaRuleManager(
            self.sigma_rules_path,
            settings_manager=self.settings_manager
        )
        self.sigma_enabled = self.settings_manager.get("sigma.enable_sigma_evaluation", True)

        # Initialize Sigma evaluator for process tree evaluation
        self.sigma_evaluator = None
        self._process_sigma_cache = {}
        if self.sigma_enabled and os.path.isdir(self.sigma_rules_path):
            try:
                self.sigma_evaluator = SigmaEvaluator()
                self.sigma_evaluator.load_rules_from_directory(self.sigma_rules_path)
            except Exception as e:
                print(f"Warning: Could not load Sigma rules for process tree: {e}")
                self.sigma_evaluator = None

        # Shared state
        self.current_case = None
        self.scan_in_progress = False
        self.cancel_scan = False
        self.progress_window = None

        # Initialize analysis modules
        self.process_monitor = ProcessMonitor(
            yara_rules_path=self.case_manager.yara_rules_path
        )
        self.persistence_monitor = PersistenceMonitor(poll_interval=5.0)
        self.http_monitor = HttpTrafficMonitor(poll_interval=1.5)
        self.http_monitor_active = False

        # Monitoring states
        self.process_monitor_active = False
        self.persistence_monitor_active = False
        self.persistence_change_count = 0

        # Auto-refresh state
        self.auto_refresh_enabled = True
        self.auto_refresh_interval = self.settings_manager.get("application.auto_refresh_interval", 2000)
        self.auto_refresh_job = None

        # YARA popup limiting
        self.popup_count_by_rule = {}
        self.max_popups_per_rule = self.settings_manager.get("application.max_popups_per_rule", 3)
        self.total_yara_matches = 0

        # Sigma match tracking
        self.sigma_popup_count_by_rule = {}
        self.total_sigma_matches = 0

        # Procmon live monitors
        self.procmon_monitors = {}

        # System-wide monitor
        self.system_wide_monitor = None
        self.system_monitor_active = False

        # Hostname resolution cache
        self.hostname_cache = {}

        # View registry
        self.views = {}
        self.active_tab = None
        self.active_analysis_subtab = None

        # Build UI
        self.create_ui()

    # ==================== UI CREATION ====================

    def create_ui(self):
        """Build the main user interface."""
        self.create_header()
        self.create_main_container()

        # Register keyboard shortcuts
        self._register_keyboard_shortcuts()

        # Bind resize event
        self._resize_after_id = None
        self.root.bind("<Configure>", self._on_window_resize)

    def create_header(self):
        """Create top header bar with date indicator."""
        header = ctk.CTkFrame(self.root, height=60, corner_radius=0,
                              fg_color=self.colors["navy"])
        header.pack(fill="x")
        header.pack_propagate(False)

        title = ctk.CTkLabel(header, text="M.A.D. - Malware Analysis Dashboard",
                             font=Fonts.title_large, text_color="white")
        title.pack(side="left", padx=20, pady=15)

        self.date_indicator_label = ctk.CTkLabel(
            header, text="", font=("Segoe UI", 12), text_color="#9ca3af")
        self.date_indicator_label.pack(side="right", padx=20, pady=15)
        self._update_date_indicator()

    def _update_date_indicator(self):
        """Refresh the date indicator in the header bar."""
        try:
            now = datetime.now()
            self.date_indicator_label.configure(
                text=now.strftime("%m/%d/%Y  %H:%M"),
                text_color="#9ca3af"
            )
        except Exception:
            pass
        self.root.after(30000, self._update_date_indicator)

    def create_main_container(self):
        """Create main layout with sidebar and content area."""
        main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=0, pady=0)

        # Create sidebar
        self.create_sidebar(main_container)

        # Create content area
        self.content_area = ctk.CTkFrame(main_container, corner_radius=0)
        self.content_area.pack(side="right", fill="both", expand=True)

        # Create analysis sub-container (shared by Processes, Live Events, Network)
        self.analysis_frame = ctk.CTkFrame(self.content_area, fg_color=self.colors["dark_blue"])
        self.analysis_title = None
        self.analysis_subtab_frame = None
        self.analysis_content = None
        self._build_analysis_frame()

        # Instantiate all views
        self.views["new_case"] = NewCaseView(self.content_area, self, self.colors)
        self.views["current_case"] = CurrentCaseView(self.content_area, self, self.colors)
        self.views["settings"] = SettingsView(self.content_area, self, self.colors)
        self.views["yara_rules"] = YaraRulesView(self.content_area, self, self.colors)

        # Analysis sub-views (parent is analysis_content, not content_area)
        self.views["processes"] = ProcessView(self.analysis_content, self, self.colors)
        self.views["live_events"] = LiveEventsView(self.analysis_content, self, self.colors)

        # Register callbacks for real-time updates
        self.process_monitor.register_process_callback(
            self.views["processes"].on_new_process_detected)
        self.persistence_monitor.register_callback(
            self.views["live_events"].on_persistence_change_detected)

        # Show initial tab
        self.show_tab("new_case")

    def _build_analysis_frame(self):
        """Build the Analysis tab container with sub-tab buttons."""
        frame = self.analysis_frame

        self.analysis_title = ctk.CTkLabel(frame, text="Analysis",
                                           font=Fonts.header_main,
                                           text_color="white")
        self.analysis_title.pack(pady=20, padx=20, anchor="w")

        # Sub-tab buttons
        self.analysis_subtab_frame = ctk.CTkFrame(frame, fg_color="transparent")
        self.analysis_subtab_frame.pack(fill="x", padx=20, pady=10)

        self.btn_processes = ctk.CTkButton(
            self.analysis_subtab_frame, text="⚙️ Processes",
            command=lambda: self.show_analysis_subtab("processes"),
            height=35, width=150,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            font=Fonts.body_bold
        )
        self.btn_processes.pack(side="left", padx=5)

        self.btn_live_events = ctk.CTkButton(
            self.analysis_subtab_frame, text="📡 Live Events",
            command=lambda: self.show_analysis_subtab("live_events"),
            height=35, width=150,
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["red"],
            font=Fonts.body_bold
        )
        self.btn_live_events.pack(side="left", padx=5)

        # Content area for analysis sub-tabs
        self.analysis_content = ctk.CTkFrame(frame, corner_radius=10,
                                             fg_color=self.colors["navy"])
        self.analysis_content.pack(fill="both", expand=True, padx=20, pady=10)

    def create_sidebar(self, parent):
        """Create left sidebar with navigation buttons."""
        self.sidebar = ctk.CTkFrame(parent, width=self._sidebar_width,
                                    corner_radius=0, fg_color=self.colors["sidebar_bg"])
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        nav_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        nav_frame.pack(fill="both", expand=True, padx=10, pady=20)

        nav_btn_height = 50 if self._is_large_screen else 36
        nav_btn_font = Fonts.label_large if self._is_large_screen else Fonts.label
        nav_btn_pady = 6 if self._is_large_screen else 3

        self.nav_buttons = {}

        nav_items = [
            ("new_case", "New Case"),
            ("current_case", "Current Case"),
            ("analysis", "Analysis"),
            ("yara_rules", "YARA Rules"),
            ("settings", "Settings"),
        ]

        for tab_name, label in nav_items:
            btn = ctk.CTkButton(
                nav_frame, text=label,
                command=lambda t=tab_name: self.show_tab(t),
                height=nav_btn_height, font=nav_btn_font,
                fg_color="transparent",
                hover_color=self.colors["navy"],
                border_width=2,
                border_color=self.colors["navy"],
                corner_radius=8
            )
            btn.pack(fill="x", pady=nav_btn_pady)
            self.nav_buttons[tab_name] = btn

    # ==================== NAVIGATION ====================

    def show_tab(self, tab_name):
        """Switch between main tabs."""
        # Hide all top-level views
        for name, view in self.views.items():
            if name not in ("processes", "live_events"):  # Analysis sub-views handled separately
                view.hide()
        self.analysis_frame.pack_forget()

        # Reset all nav button colors
        for btn in self.nav_buttons.values():
            btn.configure(fg_color="transparent", border_width=2, border_color=self.colors["navy"])

        # Show selected tab
        if tab_name == "analysis":
            self.analysis_frame.pack(fill="both", expand=True)
            self.nav_buttons["analysis"].configure(fg_color=self.colors["navy"], border_width=0)
            # Show the active analysis subtab
            if self.active_analysis_subtab:
                self.show_analysis_subtab(self.active_analysis_subtab)
            else:
                self.show_analysis_subtab("processes")
        elif tab_name in self.views:
            self.views[tab_name].show()
            if tab_name in self.nav_buttons:
                self.nav_buttons[tab_name].configure(fg_color=self.colors["navy"], border_width=0)
            # Fire on_activate for the view
            self.views[tab_name].on_activate()

        self.active_tab = tab_name

    def show_analysis_subtab(self, subtab_name):
        """Switch between analysis sub-tabs (processes, live_events)."""
        # Hide all analysis sub-views
        for name in ("processes", "live_events"):
            if name in self.views:
                self.views[name].hide()

        # Reset subtab button colors
        self.btn_processes.configure(fg_color="transparent", border_width=2, border_color=self.colors["red"])
        self.btn_live_events.configure(fg_color="transparent", border_width=2, border_color=self.colors["red"])

        # Show selected subtab
        if subtab_name in self.views:
            self.views[subtab_name].show()
            self.views[subtab_name].on_activate()

        # Highlight active button
        if subtab_name == "processes":
            self.btn_processes.configure(fg_color=self.colors["red"], border_width=0)
        elif subtab_name == "live_events":
            self.btn_live_events.configure(fg_color=self.colors["red"], border_width=0)

        self.active_analysis_subtab = subtab_name

    # ==================== KEYBOARD SHORTCUTS ====================

    def _register_keyboard_shortcuts(self):
        """Register global keyboard shortcuts for power users."""
        self.root.bind("<Control-Key-1>", lambda e: self.show_tab("new_case"))
        self.root.bind("<Control-Key-2>", lambda e: self.show_tab("current_case"))
        self.root.bind("<Control-Key-3>", lambda e: self.show_tab("analysis"))
        self.root.bind("<Control-Key-4>", lambda e: self.show_tab("yara_rules"))
        self.root.bind("<Control-Key-5>", lambda e: self.show_tab("settings"))
        self.root.bind("<F5>", lambda e: self._refresh_current_view())
        self.root.bind("<Escape>", lambda e: self._handle_escape())

        # Analysis sub-tab shortcuts
        self.root.bind("<Control-Shift-P>", lambda e: self._switch_to_analysis_subtab("processes"))
        self.root.bind("<Control-Shift-E>", lambda e: self._switch_to_analysis_subtab("live_events"))
        self.root.bind("<Control-Shift-N>", lambda e: self._switch_to_analysis_subtab("network"))

    def _refresh_current_view(self):
        """Refresh the currently active view."""
        if self.active_tab == "analysis":
            subtab = self.active_analysis_subtab
            if subtab and subtab in self.views:
                self.views[subtab].on_activate()
        elif self.active_tab and self.active_tab in self.views:
            self.views[self.active_tab].on_activate()

    def _handle_escape(self):
        """Handle escape key — close popups, collapse panels."""
        pass  # Views handle their own escape behavior

    def _switch_to_analysis_subtab(self, subtab_name):
        """Switch to analysis tab and show a specific subtab."""
        self.show_tab("analysis")
        self.show_analysis_subtab(subtab_name)

    # ==================== RESPONSIVE LAYOUT ====================

    def _on_window_resize(self, event):
        """Handle window resize with debouncing."""
        if event.widget != self.root:
            return
        if self._resize_after_id is not None:
            self.root.after_cancel(self._resize_after_id)
        self._resize_after_id = self.root.after(150, self._apply_resize_layout)

    def _apply_resize_layout(self):
        """Apply layout adjustments based on current window size."""
        try:
            win_w = self.root.winfo_width()
            is_wide = win_w >= 1400
            is_narrow = win_w < 1100

            if is_narrow:
                new_sidebar_w = 160
            elif is_wide:
                new_sidebar_w = 220
            else:
                new_sidebar_w = 190
            self.sidebar.configure(width=new_sidebar_w)

            # Update New Case form entry widths dynamically
            content_w = win_w - new_sidebar_w
            form_w = max(300, min(int(content_w * 0.45), 600))
            new_case = self.views.get("new_case")
            if new_case:
                if hasattr(new_case, 'analyst_name_entry') and new_case.analyst_name_entry:
                    new_case.analyst_name_entry.configure(width=form_w)
                if hasattr(new_case, 'report_url_entry') and new_case.report_url_entry:
                    new_case.report_url_entry.configure(width=form_w)
                if hasattr(new_case, 'url_entry') and new_case.url_entry:
                    new_case.url_entry.configure(width=form_w)
                if hasattr(new_case, 'btn_upload') and new_case.btn_upload:
                    new_case.btn_upload.configure(width=form_w)
        except Exception:
            pass

    # ==================== SHARED SCAN METHODS ====================

    def process_new_case_files(self, files, analyst_name, report_url):
        """Process files for new case with progress bar."""
        if self.scan_in_progress:
            messagebox.showwarning("Scan in Progress", "Please wait for current scan to complete")
            return

        self.scan_in_progress = True
        self.cancel_scan = False
        self.create_progress_window(len(files))

        scan_thread = threading.Thread(
            target=self._scan_files_thread,
            args=(files, analyst_name, report_url),
            daemon=True
        )
        scan_thread.start()

    def _scan_files_thread(self, files, analyst_name, report_url):
        """Background thread for file scanning."""
        try:
            case_id = f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            case_dir = os.path.join(self.case_manager.case_storage_path, case_id)
            files_dir = os.path.join(case_dir, "files")
            os.makedirs(files_dir, exist_ok=True)

            # Create network case folder if enabled
            network_case_path = ""
            if report_url and self.settings_manager.get("network.enable_network_case_folder", False):
                network_path = self.settings_manager.get_network_case_folder_path(report_url, analyst_name)
                if network_path:
                    try:
                        os.makedirs(network_path, exist_ok=True)
                        os.makedirs(os.path.join(network_path, "files"), exist_ok=True)
                        network_case_path = network_path
                        print(f"Created network case folder: {network_path}")
                    except Exception as e:
                        print(f"Warning: Could not create network folder: {e}")

            case_data = {
                "id": case_id,
                "created": datetime.now().isoformat(),
                "status": "ACTIVE",
                "analyst_name": analyst_name,
                "report_url": report_url,
                "network_case_path": network_case_path,
                "files": [],
                "total_threats": 0,
                "total_vt_hits": 0
            }

            for i, file_path in enumerate(files):
                if self.cancel_scan:
                    self.root.after(0, self.close_progress_window)
                    self.root.after(0, lambda: messagebox.showinfo("Cancelled", "Scan cancelled by user"))
                    self.scan_in_progress = False
                    return

                filename = os.path.basename(file_path)
                self.root.after(0, self.update_progress, i + 1, len(files), f"Scanning: {filename}")

                file_info = self.case_manager.process_file(file_path, files_dir, case_id)
                case_data["files"].append(file_info)

                has_yara = len(file_info["yara_matches"]) > 0
                has_thq = file_info["thq_family"] and file_info["thq_family"] not in ["Unknown", "N/A"]
                has_vt = file_info["vt_hits"] > 0

                if has_yara or has_thq or has_vt:
                    case_data["total_threats"] += 1
                case_data["total_vt_hits"] += file_info["vt_hits"]

            self.case_manager.save_case_metadata(case_dir, case_data)
            self.current_case = case_data
            self.case_manager.current_case = case_data

            self.root.after(0, self.close_progress_window)

            new_case_view = self.views.get("new_case")
            if new_case_view:
                self.root.after(0, lambda: new_case_view.status_label.configure(
                    text=f"✓ Case created: {case_data['id']} | Files: {len(files)} | Threats: {case_data['total_threats']}"
                ))

            self.root.after(0, lambda: messagebox.showinfo(
                "Success",
                f"New case created: {case_data['id']}\n"
                f"Analyst: {analyst_name}\n"
                f"Files processed: {len(files)}\n"
                f"Threats detected: {case_data['total_threats']}"
            ))

            # Clear form and switch tabs
            if new_case_view:
                self.root.after(0, new_case_view.clear_form)
            self.root.after(0, lambda: self.show_tab("current_case"))

        except Exception as e:
            self.root.after(0, self.close_progress_window)
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to create case: {str(e)}"))
            if new_case_view:
                self.root.after(0, lambda: new_case_view.status_label.configure(text="✗ Error creating case"))

        finally:
            self.scan_in_progress = False

    def process_new_case_urls(self, urls, analyst_name, report_url):
        """Process URLs for new case with progress bar."""
        if self.scan_in_progress:
            messagebox.showwarning("Scan in Progress", "Please wait for current scan to complete")
            return

        self.scan_in_progress = True
        self.cancel_scan = False
        self.create_progress_window(len(urls))

        scan_thread = threading.Thread(
            target=self._scan_urls_thread,
            args=(urls, analyst_name, report_url),
            daemon=True
        )
        scan_thread.start()

    def _scan_urls_thread(self, urls, analyst_name, report_url):
        """Background thread for URL downloading and file scanning."""
        try:
            case_id = f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            case_dir = os.path.join(self.case_manager.case_storage_path, case_id)
            files_dir = os.path.join(case_dir, "files")
            os.makedirs(files_dir, exist_ok=True)

            network_case_path = ""
            if report_url and self.settings_manager.get("network.enable_network_case_folder", False):
                network_path = self.settings_manager.get_network_case_folder_path(report_url, analyst_name)
                if network_path:
                    try:
                        os.makedirs(network_path, exist_ok=True)
                        os.makedirs(os.path.join(network_path, "files"), exist_ok=True)
                        network_case_path = network_path
                    except Exception as e:
                        print(f"Warning: Could not create network folder: {e}")

            case_data = {
                "id": case_id,
                "created": datetime.now().isoformat(),
                "status": "ACTIVE",
                "analyst_name": analyst_name,
                "report_url": report_url,
                "network_case_path": network_case_path,
                "files": [],
                "total_threats": 0,
                "total_vt_hits": 0,
                "iocs": {"urls": [], "ips": [], "domains": []}
            }

            self.case_manager.current_case = case_data
            downloaded_files = []
            failed_downloads = []

            for i, url in enumerate(urls):
                if self.cancel_scan:
                    self.root.after(0, self.close_progress_window)
                    self.root.after(0, lambda: messagebox.showinfo("Cancelled", "Scan cancelled by user"))
                    self.scan_in_progress = False
                    return

                self.root.after(0, self.update_progress, i + 1, len(urls), f"Downloading: {url[:50]}...")
                success, file_path, error = self.case_manager.download_file_from_url(url)

                if success:
                    downloaded_files.append(file_path)
                    files_to_process = [file_path]

                    if self.case_manager._is_archive(file_path):
                        self.root.after(0, self.update_progress, i + 1, len(urls), "Extracting archive...")
                        extract_success, extracted_files, extract_error = self.case_manager._extract_archive(file_path)
                        if extract_success and extracted_files:
                            files_to_process = extracted_files
                            try:
                                desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
                                archive_name = os.path.splitext(os.path.basename(file_path))[0]
                                desktop_extract_folder = os.path.join(desktop_path, f"{case_id}_{archive_name}")
                                os.makedirs(desktop_extract_folder, exist_ok=True)
                                for extracted_file in extracted_files:
                                    dest_path = os.path.join(desktop_extract_folder, os.path.basename(extracted_file))
                                    shutil.copy2(extracted_file, dest_path)
                            except Exception as e:
                                print(f"Warning: Could not copy to desktop: {e}")
                            try:
                                os.remove(file_path)
                            except:
                                pass

                    for j, process_file_path in enumerate(files_to_process):
                        filename = os.path.basename(process_file_path)
                        self.root.after(0, self.update_progress, i + 1, len(urls), f"Scanning: {filename}")
                        file_info = self.case_manager.process_file(process_file_path, files_dir, case_id)
                        file_info["source_url"] = url
                        case_data["files"].append(file_info)

                        has_yara = len(file_info["yara_matches"]) > 0
                        has_thq = file_info["thq_family"] and file_info["thq_family"] not in ["Unknown", "N/A"]
                        has_vt = file_info["vt_hits"] > 0
                        if has_yara or has_thq or has_vt:
                            case_data["total_threats"] += 1
                        case_data["total_vt_hits"] += file_info["vt_hits"]

                        try:
                            if os.path.exists(process_file_path):
                                os.remove(process_file_path)
                        except:
                            pass
                else:
                    failed_downloads.append(f"{url}: {error}")

                    import time
                    retry_result = [None]

                    def show_download_error():
                        result = messagebox.askretrycancel(
                            "Download Failed",
                            f"Failed to download file from URL:\n{url[:80]}...\n\n"
                            f"Error: {error}\n\nClick 'Retry' to try again, or 'Cancel' to skip.")
                        retry_result[0] = result

                    self.root.after(0, show_download_error)
                    while retry_result[0] is None:
                        time.sleep(0.1)

                    if retry_result[0]:
                        failed_downloads.pop()
                        self.root.after(0, self.update_progress, i + 1, len(urls), f"Retrying: {url[:50]}...")
                        success, file_path, error = self.case_manager.download_file_from_url(url)

                        if success:
                            downloaded_files.append(file_path)
                            files_to_process = [file_path]
                            if self.case_manager._is_archive(file_path):
                                self.root.after(0, self.update_progress, i + 1, len(urls), "Extracting archive...")
                                extract_success, extracted_files, extract_error = self.case_manager._extract_archive(file_path)
                                if extract_success and extracted_files:
                                    files_to_process = extracted_files
                                    try:
                                        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
                                        archive_name = os.path.splitext(os.path.basename(file_path))[0]
                                        desktop_extract_folder = os.path.join(desktop_path, f"{case_id}_{archive_name}")
                                        os.makedirs(desktop_extract_folder, exist_ok=True)
                                        for extracted_file in extracted_files:
                                            dest_path = os.path.join(desktop_extract_folder, os.path.basename(extracted_file))
                                            shutil.copy2(extracted_file, dest_path)
                                    except Exception as e:
                                        print(f"Warning: Could not copy to desktop: {e}")
                                    try:
                                        os.remove(file_path)
                                    except:
                                        pass

                            for j, process_file_path in enumerate(files_to_process):
                                filename = os.path.basename(process_file_path)
                                self.root.after(0, self.update_progress, i + 1, len(urls), f"Scanning: {filename}")
                                file_info = self.case_manager.process_file(process_file_path, files_dir, case_id)
                                file_info["source_url"] = url
                                case_data["files"].append(file_info)
                                has_yara = len(file_info["yara_matches"]) > 0
                                has_thq = file_info["thq_family"] and file_info["thq_family"] not in ["Unknown", "N/A"]
                                has_vt = file_info["vt_hits"] > 0
                                if has_yara or has_thq or has_vt:
                                    case_data["total_threats"] += 1
                                case_data["total_vt_hits"] += file_info["vt_hits"]
                                try:
                                    if os.path.exists(process_file_path):
                                        os.remove(process_file_path)
                                except:
                                    pass
                        else:
                            failed_downloads.append(f"{url}: {error} (retry failed)")

            self.case_manager.save_case_metadata(case_dir, case_data)
            self.current_case = case_data
            self.case_manager.current_case = case_data

            self.root.after(0, self.close_progress_window)

            files_processed = len(case_data["files"])
            success_msg = (f"New case created: {case_data['id']}\n"
                           f"Analyst: {analyst_name}\n"
                           f"URLs processed: {len(urls)}\n"
                           f"Files analyzed: {files_processed}\n"
                           f"Threats detected: {case_data['total_threats']}")

            if failed_downloads:
                success_msg += f"\n\nFailed downloads ({len(failed_downloads)}):\n"
                success_msg += "\n".join(failed_downloads[:5])
                if len(failed_downloads) > 5:
                    success_msg += f"\n... and {len(failed_downloads) - 5} more"

            new_case_view = self.views.get("new_case")
            if new_case_view:
                self.root.after(0, lambda: new_case_view.status_label.configure(
                    text=f"✓ Case created: {case_data['id']} | Files: {files_processed} | Threats: {case_data['total_threats']}"
                ))

            self.root.after(0, lambda: messagebox.showinfo("Success", success_msg))

            if new_case_view:
                self.root.after(0, new_case_view.clear_form)
            self.root.after(0, lambda: self.show_tab("current_case"))

        except Exception as e:
            self.root.after(0, self.close_progress_window)
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to create case: {str(e)}"))
            import traceback
            traceback.print_exc()

        finally:
            self.scan_in_progress = False

    # ==================== PROGRESS WINDOW ====================

    def create_progress_window(self, total_files):
        """Create progress window."""
        self.progress_window = ctk.CTkToplevel(self.root)
        self.progress_window.title("Scanning Files")
        self.progress_window.geometry("550x250")
        self.progress_window.transient(self.root)
        self.progress_window.grab_set()
        self.progress_window.resizable(False, False)

        self.progress_window.update_idletasks()
        x = (self.progress_window.winfo_screenwidth() // 2) - (550 // 2)
        y = (self.progress_window.winfo_screenheight() // 2) - (250 // 2)
        self.progress_window.geometry(f"550x250+{x}+{y}")

        container = ctk.CTkFrame(self.progress_window, fg_color="transparent")
        container.pack(fill="both", expand=True, padx=30, pady=30)

        title = ctk.CTkLabel(container, text="Scanning Files", font=Fonts.title_large)
        title.pack(pady=(0, 5))

        subtitle = ctk.CTkLabel(container, text="YARA & Threat Intelligence Analysis",
                                font=Fonts.body, text_color="gray60")
        subtitle.pack(pady=(0, 20))

        self.progress_bar = ctk.CTkProgressBar(container, width=450, height=20)
        self.progress_bar.pack(pady=10)
        self.progress_bar.set(0)

        self.progress_label = ctk.CTkLabel(
            container, text=f"Processing 0 of {total_files} files...",
            font=Fonts.body_large_bold)
        self.progress_label.pack(pady=10)

        self.current_file_label = ctk.CTkLabel(
            container, text="Initializing...",
            font=Fonts.helper, text_color="gray60")
        self.current_file_label.pack(pady=5)

        cancel_btn = ctk.CTkButton(
            container, text="Cancel Scan",
            command=self.cancel_scan_operation,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            width=120, height=35)
        cancel_btn.pack(pady=15)

    def update_progress(self, current, total, current_file):
        """Update progress bar and labels."""
        if self.progress_window and self.progress_window.winfo_exists():
            progress = current / total
            self.progress_bar.set(progress)
            self.progress_label.configure(text=f"Processing {current} of {total} files...")
            self.current_file_label.configure(text=current_file)

    def cancel_scan_operation(self):
        """Cancel the current scan."""
        self.cancel_scan = True
        if self.progress_window and self.progress_window.winfo_exists():
            self.progress_window.destroy()

    def close_progress_window(self):
        """Close progress window."""
        if self.progress_window and self.progress_window.winfo_exists():
            self.progress_window.destroy()
            self.progress_window = None

    # ==================== FILE ADD TO CASE ====================

    def handle_add_files(self):
        """Handle adding files to existing case."""
        if not self.current_case:
            messagebox.showwarning("No Case", "Please create a case first")
            return

        if self.scan_in_progress:
            messagebox.showwarning("Scan in Progress", "Please wait for current scan to complete")
            return

        files = filedialog.askopenfilenames(title="Add files to case")
        if not files:
            return

        self.scan_in_progress = True
        self.cancel_scan = False
        self.create_progress_window(len(files))

        def add_files_thread():
            try:
                case_id = self.current_case["id"]
                case_dir = os.path.join(self.case_manager.case_storage_path, case_id)
                files_dir = os.path.join(case_dir, "files")

                for i, file_path in enumerate(files):
                    if self.cancel_scan:
                        self.root.after(0, self.close_progress_window)
                        self.root.after(0, lambda: messagebox.showinfo("Cancelled", "Scan cancelled by user"))
                        self.scan_in_progress = False
                        return

                    filename = os.path.basename(file_path)
                    self.root.after(0, self.update_progress, i + 1, len(files), f"Scanning: {filename}")

                    file_info = self.case_manager.process_file(file_path, files_dir, case_id)
                    self.current_case["files"].append(file_info)

                    if not file_info.get("whitelisted", False):
                        has_yara = len(file_info["yara_matches"]) > 0
                        has_thq = file_info["thq_family"] and file_info["thq_family"] not in ["Unknown", "N/A"]
                        has_vt = file_info["vt_hits"] > 0
                        if has_yara or has_thq or has_vt:
                            self.current_case["total_threats"] += 1
                        self.current_case["total_vt_hits"] += file_info["vt_hits"]

                self.case_manager.save_case_metadata(case_dir, self.current_case)

                self.root.after(0, self.close_progress_window)
                current_case_view = self.views.get("current_case")
                if current_case_view:
                    self.root.after(0, current_case_view.update_display)
                self.root.after(0, lambda: messagebox.showinfo(
                    "Success",
                    f"Added {len(files)} files to case\n"
                    f"Total files: {len(self.current_case['files'])}\n"
                    f"Total threats: {self.current_case['total_threats']}"
                ))

            except Exception as e:
                self.root.after(0, self.close_progress_window)
                self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to add files: {str(e)}"))
                import traceback
                traceback.print_exc()

            finally:
                self.scan_in_progress = False

        thread = threading.Thread(target=add_files_thread, daemon=True)
        thread.start()

    # ==================== FILE VIEWER UTILITIES ====================

    def view_file_strings(self, file_path, file_name):
        """View extracted strings from a static file in a dedicated window."""
        strings_window = ctk.CTkToplevel(self.root)
        strings_window.title(f"File Strings: {file_name}")
        strings_window.geometry("1000x700")

        main_container = ctk.CTkFrame(strings_window, fg_color=self.colors["dark_blue"])
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        header = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=60)
        header.pack(fill="x", padx=0, pady=(0, 10))
        header.pack_propagate(False)

        title = ctk.CTkLabel(header, text=f"📄 {file_name}", font=Fonts.logo_subtitle)
        title.pack(side="left", padx=20, pady=15)

        search_frame = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=90)
        search_frame.pack(fill="x", padx=10, pady=10)
        search_frame.pack_propagate(False)

        search_row = ctk.CTkFrame(search_frame, fg_color="transparent")
        search_row.pack(fill="x", padx=5, pady=(5, 0))

        ctk.CTkLabel(search_row, text="🔍 Search:", font=Fonts.body_bold).pack(side="left", padx=(10, 5))

        search_entry = ctk.CTkEntry(search_row, width=300, height=35,
                                    placeholder_text="Enter search term...", font=Fonts.body)
        search_entry.pack(side="left", padx=5)

        status_label = ctk.CTkLabel(search_row, text="Extracting strings...",
                                    font=Fonts.helper, text_color="gray60")
        status_label.pack(side="left", padx=20)

        filter_row = ctk.CTkFrame(search_frame, fg_color="transparent")
        filter_row.pack(fill="x", padx=5, pady=(5, 5))

        ctk.CTkLabel(filter_row, text="📏 Length:", font=Fonts.body_bold).pack(side="left", padx=(10, 5))
        ctk.CTkLabel(filter_row, text="Min:", font=Fonts.helper).pack(side="left", padx=(5, 2))
        min_length_entry = ctk.CTkEntry(filter_row, width=60, height=30, placeholder_text="4", font=Fonts.helper)
        min_length_entry.insert(0, "4")
        min_length_entry.pack(side="left", padx=2)
        ctk.CTkLabel(filter_row, text="Max:", font=Fonts.helper).pack(side="left", padx=(10, 2))
        max_length_entry = ctk.CTkEntry(filter_row, width=60, height=30, placeholder_text="∞", font=Fonts.helper)
        max_length_entry.pack(side="left", padx=2)

        quality_filter_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(filter_row, text="Quality Filter", variable=quality_filter_var,
                        font=Fonts.helper, checkbox_width=20, checkbox_height=20).pack(side="left", padx=15)

        export_btn = ctk.CTkButton(filter_row, text="💾 Export TXT", command=lambda: None,
                                   height=30, width=120, fg_color=self.colors["red"],
                                   hover_color=self.colors["red_dark"], font=Fonts.label)
        export_btn.pack(side="left", padx=5)

        strings_text_frame = ctk.CTkFrame(main_container, fg_color="gray20")
        strings_text_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        vsb = tk.Scrollbar(strings_text_frame, orient="vertical", bg="#1a1a1a")
        vsb.pack(side="right", fill="y")
        hsb = tk.Scrollbar(strings_text_frame, orient="horizontal", bg="#1a1a1a")
        hsb.pack(side="bottom", fill="x")

        strings_text = tk.Text(strings_text_frame, wrap="none", bg="#1a1a1a", fg="#ffffff",
                               font=Fonts.monospace(10), yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        strings_text.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        vsb.config(command=strings_text.yview)
        hsb.config(command=strings_text.xview)

        extraction_data = {"strings": [], "extraction_result": None}

        def search_strings(event=None):
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
                        filter_msg = f" (filtered by length: {min_len}-{max_len if max_len != float('inf') else '∞'})"
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
                        filter_msg = f" (length: {min_len}-{max_len if max_len != float('inf') else '∞'})"
                    status_label.configure(text=f"Found: {len(filtered)} matches{filter_msg}")
                else:
                    strings_text.insert("1.0", f"No strings found matching '{search_term}'")
                    status_label.configure(text="No matches")

            strings_text.configure(state="disabled")

        search_entry.bind("<KeyRelease>", search_strings)
        min_length_entry.bind("<KeyRelease>", search_strings)
        max_length_entry.bind("<KeyRelease>", search_strings)

        def extract_file_strings():
            try:
                status_label.configure(text="Extracting strings from file...")
                export_btn.configure(state="disabled")

                import sys
                sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'analysis_modules'))
                from file_string_extractor import FileStringExtractor
                extractor = FileStringExtractor(verbose=True)
                use_quality_filter = quality_filter_var.get()

                def progress_callback(bytes_processed, total_bytes, current_strings):
                    pct = (bytes_processed / total_bytes * 100) if total_bytes > 0 else 0
                    self.root.after(0, lambda: status_label.configure(
                        text=f"Extracting: {pct:.0f}% ({current_strings} strings so far...)"))

                result = extractor.extract_strings_from_file(
                    file_path, min_length=4, max_strings=50000,
                    include_unicode=True, enable_quality_filter=use_quality_filter,
                    progress_callback=progress_callback, scan_mode="quick")

                all_strings = []
                for category, strings in result['strings'].items():
                    all_strings.extend(strings)

                extraction_data["strings"] = all_strings
                extraction_data["extraction_result"] = result

                if self.current_case and self.current_case.get("network_case_path"):
                    try:
                        network_path = self.current_case["network_case_path"]
                        strings_filename = f"{os.path.splitext(file_name)[0]}_strings.txt"
                        network_strings_path = os.path.join(network_path, strings_filename)
                        extractor.export_to_txt(result, network_strings_path, include_metadata=True)
                    except Exception as e:
                        print(f"Warning: Could not auto-save strings to network folder: {e}")

                self.root.after(0, lambda: status_label.configure(
                    text=f"Complete: {len(all_strings)} strings extracted in {result.get('extraction_time', 0):.2f}s"))
                self.root.after(0, lambda: export_btn.configure(state="normal"))
                self.root.after(0, search_strings)

            except Exception as e:
                import traceback
                traceback.print_exc()
                self.root.after(0, lambda: status_label.configure(text=f"Error: {str(e)}"))
                self.root.after(0, lambda: strings_text.configure(state="normal"))
                self.root.after(0, lambda: strings_text.delete("1.0", "end"))
                self.root.after(0, lambda: strings_text.insert("1.0", f"Error extracting strings:\n{str(e)}"))
                self.root.after(0, lambda: strings_text.configure(state="disabled"))
                self.root.after(0, lambda: export_btn.configure(state="normal"))

        def export_file_strings():
            try:
                if not extraction_data["extraction_result"]:
                    messagebox.showwarning("No Data", "No strings available to export")
                    return

                default_name = f"{os.path.splitext(file_name)[0]}_strings.txt"
                save_path = filedialog.asksaveasfilename(
                    title="Export Strings", defaultextension=".txt",
                    initialfile=default_name,
                    filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
                if not save_path:
                    return

                import sys
                sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'analysis_modules'))
                from file_string_extractor import FileStringExtractor
                extractor = FileStringExtractor()
                success = extractor.export_to_txt(
                    extraction_data["extraction_result"], save_path, include_metadata=True)

                if success:
                    network_copy_msg = ""
                    if self.current_case and self.current_case.get("network_case_path"):
                        try:
                            network_path = self.current_case["network_case_path"]
                            network_strings_path = os.path.join(network_path, os.path.basename(save_path))
                            shutil.copy2(save_path, network_strings_path)
                            network_copy_msg = f"\n\nAlso copied to network folder:\n{network_strings_path}"
                        except Exception as e:
                            print(f"Warning: Could not copy strings to network folder: {e}")
                    messagebox.showinfo("Export Complete", f"Strings exported to:\n{save_path}{network_copy_msg}")
                else:
                    messagebox.showerror("Export Failed", "Failed to export strings")
            except Exception as e:
                messagebox.showerror("Export Error", f"Error exporting:\n{str(e)}")

        export_btn.configure(command=export_file_strings)
        quality_filter_checkbox = filter_row.winfo_children()[-2]  # Get checkbox from row
        quality_filter_var.trace_add("write", lambda *_: threading.Thread(target=extract_file_strings, daemon=True).start())

        threading.Thread(target=extract_file_strings, daemon=True).start()

    def view_file_hex(self, file_path, file_name):
        """View file in hex format."""
        viewer = get_viewer_executor()

        hex_window = ctk.CTkToplevel(self.root)
        hex_window.title(f"Hex View: {file_name}")
        hex_window.geometry("1200x700")

        main_container = ctk.CTkFrame(hex_window, fg_color=self.colors["dark_blue"])
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        header = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=60)
        header.pack(fill="x", padx=0, pady=(0, 10))
        header.pack_propagate(False)

        ctk.CTkLabel(header, text=f"🔍 Hex View: {file_name}",
                     font=Fonts.logo_subtitle).pack(side="left", padx=20, pady=15)

        file_info = viewer.get_file_info(file_path)
        ctk.CTkLabel(header, text=f"Size: {file_info.get('size_kb', 0):.2f} KB",
                     font=Fonts.helper, text_color="gray60").pack(side="right", padx=20)

        text_frame = ctk.CTkFrame(main_container, fg_color=self.colors["navy"])
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        hex_text = tk.Text(text_frame, wrap="none", bg="#0d1520", fg="#ffffff",
                           font=("Courier New", 10), selectbackground="#2a4d6e",
                           selectforeground="#ffffff")

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

    def view_file_text(self, file_path, file_name):
        """View file as text."""
        viewer = get_viewer_executor()

        text_window = ctk.CTkToplevel(self.root)
        text_window.title(f"Text View: {file_name}")
        text_window.geometry("1200x700")

        main_container = ctk.CTkFrame(text_window, fg_color=self.colors["dark_blue"])
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        header = ctk.CTkFrame(main_container, fg_color=self.colors["navy"], height=60)
        header.pack(fill="x", padx=0, pady=(0, 10))
        header.pack_propagate(False)

        ctk.CTkLabel(header, text=f"📄 Text View: {file_name}",
                     font=Fonts.logo_subtitle).pack(side="left", padx=20, pady=15)

        file_info = viewer.get_file_info(file_path)
        ctk.CTkLabel(header, text=f"Size: {file_info.get('size_kb', 0):.2f} KB",
                     font=Fonts.helper, text_color="gray60").pack(side="right", padx=20)

        text_frame = ctk.CTkFrame(main_container, fg_color=self.colors["navy"])
        text_frame.pack(fill="both", expand=True, padx=10, pady=10)

        line_frame = tk.Frame(text_frame, bg="#0d1520")
        line_frame.pack(side="left", fill="y")

        line_numbers = tk.Text(line_frame, width=6, wrap="none", bg="#1a2332", fg="gray60",
                               font=("Courier New", 10), state="disabled", takefocus=0)
        line_numbers.pack(side="left", fill="y")

        text_widget = tk.Text(text_frame, wrap="none", bg="#0d1520", fg="#ffffff",
                              font=("Courier New", 10), selectbackground="#2a4d6e",
                              selectforeground="#ffffff")

        vsb = ttk.Scrollbar(text_frame, orient="vertical", command=text_widget.yview)
        hsb = ttk.Scrollbar(text_frame, orient="horizontal", command=text_widget.xview)
        text_widget.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        text_widget.pack(side="left", fill="both", expand=True)

        def load_text():
            text_content, lines_read = viewer.read_file_as_text(file_path, max_lines=10000)
            text_widget.delete("1.0", "end")
            text_widget.insert("1.0", text_content)

            line_numbers.configure(state="normal")
            line_numbers.delete("1.0", "end")
            for i in range(1, min(lines_read + 1, 10001)):
                line_numbers.insert("end", f"{i:5d}\n")
            line_numbers.configure(state="disabled")
            text_widget.configure(state="disabled")

        threading.Thread(target=load_text, daemon=True).start()

    def execute_file(self, file_path, file_name, suspended=False):
        """Execute file and redirect to Analysis tab."""
        viewer = get_viewer_executor()

        if not viewer.can_execute(file_path):
            messagebox.showerror("Cannot Execute",
                                 f"This file type cannot be executed:\n{file_name}")
            return

        if suspended:
            confirm = messagebox.askyesno(
                "Confirm Suspended Execution",
                f"Execute '{file_name}' in SUSPENDED state?\n\n"
                "The process will be created but immediately suspended.\n"
                "You can resume it from the Analysis tab.")
        else:
            confirm = messagebox.askyesno(
                "Confirm Execution",
                f"Execute '{file_name}'?\n\n"
                "WARNING: This will run the file on your system.\n"
                "Make sure you are in a safe analysis environment.")

        if not confirm:
            return

        exec_result = viewer.execute_file(file_path, suspended=suspended)

        if not exec_result.get('success', False):
            messagebox.showerror("Execution Error", exec_result.get('error', 'Unknown error'))
            return

        pid = exec_result.get('pid', None)

        if suspended:
            messagebox.showinfo("Process Created",
                                f"Process created in SUSPENDED state!\n\nPID: {pid}\nFile: {file_name}\n\nSwitching to Analysis tab...")
        else:
            if pid:
                messagebox.showinfo("Process Launched",
                                    f"Process launched successfully!\n\nPID: {pid}\nFile: {file_name}\n\nSwitching to Analysis tab...")

        self.show_tab("analysis")

        if pid:
            process_view = self.views.get("processes")
            if process_view:
                self.root.after(500, lambda: process_view.focus_process_by_pid(pid))

    # ==================== SHARED UTILITIES ====================

    def evaluate_process_sigma(self, proc):
        """
        Evaluate a process dict against Sigma process_creation rules.
        Returns list of matching rule titles (cached by exe path).
        """
        if not self.sigma_evaluator:
            return []

        exe = proc.get('exe', '')
        if not exe or exe == 'N/A':
            return []

        # Check cache first
        if exe in self._process_sigma_cache:
            return self._process_sigma_cache[exe]

        # Build a Sigma-compatible event dict for process_creation (event_id=1)
        event_dict = {
            'Image': exe,
            'CommandLine': proc.get('cmdline', exe),
            'ParentImage': proc.get('parent_exe', ''),
            'User': proc.get('username', ''),
            'ProcessId': str(proc.get('pid', '')),
        }

        try:
            matches = self.sigma_evaluator._evaluate(event_dict, event_id=1)
            match_titles = [m.rule.title for m in matches]
            self._process_sigma_cache[exe] = match_titles
            return match_titles
        except Exception:
            self._process_sigma_cache[exe] = []
            return []

    def should_show_popup(self, rule_name):
        """
        Determine if a popup should be shown for this YARA rule.
        Limits popups to max_popups_per_rule per rule family to reduce alert fatigue.
        """
        if not rule_name or rule_name == 'No_YARA_Hit':
            return False

        count = self.popup_count_by_rule.get(rule_name, 0)

        if count < self.max_popups_per_rule:
            self.popup_count_by_rule[rule_name] = count + 1
            return True
        else:
            print(f"ℹ️  Popup suppressed for {rule_name} (limit: {self.max_popups_per_rule} per rule)")
            return False

    def resolve_hostname(self, ip_address):
        """Resolve IP address to hostname with caching."""
        if ip_address in self.hostname_cache:
            return self.hostname_cache[ip_address]

        if ip_address in ['', '0.0.0.0', '127.0.0.1', 'localhost', '*']:
            self.hostname_cache[ip_address] = '-'
            return '-'

        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            self.hostname_cache[ip_address] = hostname
            return hostname
        except:
            self.hostname_cache[ip_address] = '-'
            return '-'

    # ==================== APPLICATION LIFECYCLE ====================

    def run(self):
        """Start the application."""
        self.root.after(100, self._start_monitoring)
        self.root.mainloop()

    def _start_monitoring(self):
        """Called after main window is visible to start background monitoring."""
        if not self.process_monitor_active:
            self.process_monitor.start_monitoring()
            self.process_monitor_active = True
            process_view = self.views.get("processes")
            if process_view and hasattr(process_view, 'btn_toggle_process_monitor'):
                process_view.btn_toggle_process_monitor.configure(text="⏸ Stop Monitoring")
            if process_view:
                process_view.start_auto_refresh()

        if not self.persistence_monitor_active:
            self.persistence_monitor.start_monitoring()
            self.persistence_monitor_active = True


# Main entry point
if __name__ == "__main__":
    app = ForensicAnalysisGUI()
    app.run()
