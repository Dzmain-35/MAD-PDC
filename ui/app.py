"""
MAD Application Controller
Main application class that orchestrates all UI components.

This is a transitional module that allows gradual migration from the monolithic MAD.py.
Import and use the modular tab components while maintaining backward compatibility.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime
import os
import sys
import threading
import subprocess
import platform
import webbrowser

from PIL import Image

# Add parent directory to path for imports when running from ui/
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

# Import managers
from case_manager import CaseManager
from yara_rule_manager import YaraRuleManager
from settings_manager import SettingsManager

# Import analysis modules
from analysis_modules.process_monitor import ProcessMonitor
from analysis_modules.network_monitor import NetworkMonitor
from analysis_modules.procmon_events import ProcmonLiveMonitor, ProcmonEvent
from analysis_modules.system_wide_monitor import SystemWideMonitor, EventFilter
from analysis_modules.sysmon_parser import SysmonLogMonitor

# Import UI components
from typography import Fonts
from ui.theme import Theme, Colors
from ui.tabs import (
    NewCaseTab, CurrentCaseTab, AnalysisTab,
    YaraRulesTab, SettingsTab
)
from ui.dialogs import ProgressDialog, YaraAddDialog, YaraEditDialog, YaraViewDialog

# Import handlers
from handlers import CaseHandlers, ProcessHandlers, NetworkHandlers, FileHandlers


class ForensicAnalysisGUI:
    """
    Main application controller for MAD - Malware Analysis Dashboard.

    This class orchestrates all UI components and manages the application state.
    """

    def __init__(self):
        # Apply theme
        Theme.apply()

        # Initialize main window
        self.root = ctk.CTk()
        self.root.title(Theme.TITLE)
        self.root.geometry(Theme.DEFAULT_GEOMETRY)

        # Color scheme (backward compatibility)
        self.colors = Colors.as_dict()

        # Initialize managers
        self._init_managers()

        # Initialize analysis modules
        self._init_analysis_modules()

        # Initialize state
        self._init_state()

        # Initialize handlers
        self._init_handlers()

        # Create UI
        self._create_ui()

    def _init_managers(self):
        """Initialize all manager classes"""
        # Settings manager first
        self.settings_manager = SettingsManager()
        print("Settings loaded successfully")

        # Get API keys from settings
        vt_api_key = self.settings_manager.get("api_keys.virustotal")
        threathq_user = self.settings_manager.get("api_keys.threathq_user")
        threathq_pass = self.settings_manager.get("api_keys.threathq_pass")

        # Case manager with API keys
        self.case_manager = CaseManager(
            vt_api_key=vt_api_key if vt_api_key else None,
            threathq_user=threathq_user if threathq_user else None,
            threathq_pass=threathq_pass if threathq_pass else None,
            settings_manager=self.settings_manager
        )
        print(f"Case storage initialized at: {self.case_manager.case_storage_path}")

        # YARA rule manager
        self.yara_rule_manager = YaraRuleManager(
            self.case_manager.yara_rules_path,
            settings_manager=self.settings_manager
        )

    def _init_analysis_modules(self):
        """Initialize analysis modules"""
        self.process_monitor = ProcessMonitor(
            yara_rules_path=self.case_manager.yara_rules_path
        )
        self.network_monitor = NetworkMonitor()

        # Register callbacks
        self.process_monitor.register_process_callback(self.on_new_process_detected)
        self.network_monitor.register_connection_callback(self.on_new_connection_detected)

        # System-wide monitor (initialized on demand)
        self.system_wide_monitor = None

    def _init_state(self):
        """Initialize application state"""
        # Case state
        self.current_case = None
        self.scan_in_progress = False
        self.cancel_scan = False
        self.progress_window = None

        # Monitoring states
        self.process_monitor_active = False
        self.network_monitor_active = False
        self.system_monitor_active = False

        # Auto-refresh settings
        self.auto_refresh_enabled = True
        self.auto_refresh_interval = self.settings_manager.get(
            "application.auto_refresh_interval", 2000
        )
        self.auto_refresh_job = None

        # Process tree tracking
        self.pid_to_tree_item = {}
        self.process_tree_initial_load = True

        # YARA popup limiting
        self.popup_count_by_rule = {}
        self.max_popups_per_rule = self.settings_manager.get(
            "application.max_popups_per_rule", 3
        )
        self.total_yara_matches = 0

        # Procmon live monitors
        self.procmon_monitors = {}

        # Live events toggle callback
        self.live_events_toggle_monitoring = None

    def _init_handlers(self):
        """Initialize business logic handlers"""
        self.case_handlers = CaseHandlers(self)
        self.process_handlers = ProcessHandlers(self)
        self.network_handlers = NetworkHandlers(self)
        self.file_handlers = FileHandlers(self)

    def _create_ui(self):
        """Build the main user interface"""
        self._create_header()
        self._create_main_container()

    def _create_header(self):
        """Create top header bar"""
        header = ctk.CTkFrame(
            self.root, height=60, corner_radius=0,
            fg_color=self.colors["navy"]
        )
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        title = ctk.CTkLabel(
            header, text="MAD - Malware Analysis Dashboard",
            font=Fonts.header_subsection,
            text_color="white"
        )
        title.pack(side="left", padx=20, pady=15)

    def _create_main_container(self):
        """Create main layout with sidebar and content area"""
        main_container = ctk.CTkFrame(self.root, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=0, pady=0)

        # Create sidebar
        self._create_sidebar(main_container)

        # Create content area
        self.content_area = ctk.CTkFrame(main_container, corner_radius=0)
        self.content_area.pack(side="right", fill="both", expand=True)

        # Create tabs using modular components
        self.tabs = {}
        self.tab_objects = {}

        self._create_tabs()

        # Show initial tab
        self.show_tab("new_case")

    def _create_sidebar(self, parent):
        """Create left sidebar with navigation buttons"""
        self.sidebar = ctk.CTkFrame(
            parent, width=200, corner_radius=0,
            fg_color=self.colors["sidebar_bg"]
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        nav_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        nav_frame.pack(fill="both", expand=True, padx=10, pady=20)

        # Navigation buttons
        button_config = {
            "height": 45,
            "font": Fonts.label_large,
            "corner_radius": 8
        }

        self.btn_new_case = ctk.CTkButton(
            nav_frame, text="New Case",
            command=lambda: self.show_tab("new_case"),
            fg_color=self.colors["navy"],
            hover_color=self.colors["dark_blue"],
            **button_config
        )
        self.btn_new_case.pack(fill="x", pady=5)

        self.btn_current_case = ctk.CTkButton(
            nav_frame, text="Current Case",
            command=lambda: self.show_tab("current_case"),
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["navy"],
            **button_config
        )
        self.btn_current_case.pack(fill="x", pady=5)

        self.btn_analysis = ctk.CTkButton(
            nav_frame, text="Analysis",
            command=lambda: self.show_tab("analysis"),
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["navy"],
            **button_config
        )
        self.btn_analysis.pack(fill="x", pady=5)

        self.btn_yara_rules = ctk.CTkButton(
            nav_frame, text="YARA Rules",
            command=lambda: self.show_tab("yara_rules"),
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["navy"],
            **button_config
        )
        self.btn_yara_rules.pack(fill="x", pady=5)

        self.btn_settings = ctk.CTkButton(
            nav_frame, text="Settings",
            command=lambda: self.show_tab("settings"),
            fg_color="transparent",
            hover_color=self.colors["navy"],
            border_width=2,
            border_color=self.colors["navy"],
            **button_config
        )
        self.btn_settings.pack(fill="x", pady=5)

        # Store button references for styling
        self.nav_buttons = {
            "new_case": self.btn_new_case,
            "current_case": self.btn_current_case,
            "analysis": self.btn_analysis,
            "yara_rules": self.btn_yara_rules,
            "settings": self.btn_settings,
        }

    def _create_tabs(self):
        """Create all tabs using modular components"""
        # New Case Tab
        new_case_tab = NewCaseTab(self, self.content_area)
        self.tabs["new_case"] = new_case_tab.create()
        self.tab_objects["new_case"] = new_case_tab

        # Current Case Tab
        current_case_tab = CurrentCaseTab(self, self.content_area)
        self.tabs["current_case"] = current_case_tab.create()
        self.tab_objects["current_case"] = current_case_tab

        # Analysis Tab (includes subtabs)
        analysis_tab = AnalysisTab(self, self.content_area)
        self.tabs["analysis"] = analysis_tab.create()
        self.tab_objects["analysis"] = analysis_tab

        # YARA Rules Tab
        yara_rules_tab = YaraRulesTab(self, self.content_area)
        self.tabs["yara_rules"] = yara_rules_tab.create()
        self.tab_objects["yara_rules"] = yara_rules_tab

        # Settings Tab
        settings_tab = SettingsTab(self, self.content_area)
        self.tabs["settings"] = settings_tab.create()
        self.tab_objects["settings"] = settings_tab

    def show_tab(self, tab_name: str):
        """Switch between main tabs"""
        # Hide all tabs
        for tab in self.tabs.values():
            tab.pack_forget()

        # Reset all button styles
        for btn in self.nav_buttons.values():
            btn.configure(
                fg_color="transparent",
                border_width=2,
                border_color=self.colors["navy"]
            )

        # Show selected tab
        if tab_name in self.tabs:
            self.tabs[tab_name].pack(fill="both", expand=True)

            # Highlight active button
            if tab_name in self.nav_buttons:
                self.nav_buttons[tab_name].configure(
                    fg_color=self.colors["navy"],
                    border_width=0
                )

            # Call tab's on_show method
            if tab_name in self.tab_objects:
                self.tab_objects[tab_name].on_show()

    # ==================== APPLICATION LIFECYCLE ====================

    def run(self):
        """Start the application"""
        # Auto-start process monitoring
        # Note: callback is already registered in _init_analysis_modules()
        if not self.process_monitor_active:
            self.process_monitor.start_monitoring()
            self.process_monitor_active = True
            if hasattr(self, 'btn_toggle_process_monitor'):
                self.btn_toggle_process_monitor.configure(text="Stop Monitoring")
            self.start_auto_refresh()

        self.root.mainloop()

    def switch_tab(self, tab_name: str):
        """Alias for show_tab for compatibility"""
        self.show_tab(tab_name)

    # ==================== CASE HANDLERS (delegated) ====================

    def handle_new_case_upload(self, case_name, analyst_name, report_url, files, progress_callback=None):
        """Handle file upload for new case"""
        return self.case_handlers.handle_new_case_upload(
            case_name, analyst_name, report_url, files, progress_callback
        )

    def handle_add_files(self, files, progress_callback=None):
        """Handle adding files to case"""
        return self.case_handlers.handle_add_files(files, progress_callback)

    def handle_add_ioc(self):
        """Handle adding IOC"""
        self.case_handlers.show_add_ioc_dialog()

    def handle_save_notes(self):
        """Handle saving notes"""
        self.case_handlers.handle_save_notes()

    def update_current_case_display(self):
        """Update current case display"""
        if "current_case" in self.tab_objects:
            self.tab_objects["current_case"].refresh()

    def refresh_iocs_display(self):
        """Refresh IOCs display"""
        self.case_handlers.refresh_iocs_display()

    def delete_file_from_case(self, file_info, card_frame):
        """Delete file from case"""
        return self.case_handlers.delete_file_from_case(file_info, card_frame)

    def export_case(self, export_format="json"):
        """Export current case"""
        return self.case_handlers.export_case(export_format)

    # ==================== PROCESS HANDLERS (delegated) ====================

    def toggle_process_monitoring(self):
        """Toggle process monitoring"""
        self.process_handlers.toggle_process_monitoring()

    def refresh_process_list(self):
        """Refresh process list"""
        self.process_handlers.refresh_process_list()

    def filter_processes(self):
        """Filter processes"""
        self.process_handlers.filter_processes()

    def clear_process_search(self):
        """Clear process search"""
        self.process_handlers.clear_process_search()

    def scan_selected_process(self):
        """Scan selected process with YARA"""
        self.process_handlers.scan_selected_process()

    def scan_all_processes(self):
        """Scan all processes with YARA"""
        self.process_handlers.scan_all_processes()

    def kill_selected_process(self):
        """Kill selected process"""
        self.process_handlers.kill_selected_process()

    def suspend_selected_process(self):
        """Suspend selected process"""
        self.process_handlers.suspend_selected_process()

    def resume_selected_process(self):
        """Resume selected process"""
        self.process_handlers.resume_selected_process()

    def open_folder_location(self):
        """Open folder location of selected process"""
        self.process_handlers.open_folder_location()

    def view_process_details_and_strings(self):
        """View process details and strings"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process")
            return
        item = self.process_tree.item(selection[0])
        pid = int(item['values'][0])
        name = item['values'][1]
        self.file_handlers.view_process_strings(pid, name)

    def show_process_context_menu(self, event):
        """Show process context menu"""
        try:
            self.process_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.process_context_menu.grab_release()

    def on_new_process_detected(self, proc_info):
        """Callback for new process detection"""
        if proc_info and proc_info.get('threat_detected'):
            self.total_yara_matches += 1
            self.root.after(0, self.update_yara_match_badge)

    def start_auto_refresh(self):
        """Start auto-refreshing process and network lists"""
        if self.auto_refresh_enabled and self.process_monitor_active:
            self.refresh_process_list()
            self.auto_refresh_job = self.root.after(
                self.auto_refresh_interval,
                self.start_auto_refresh
            )

    def stop_auto_refresh(self):
        """Stop auto-refresh"""
        if self.auto_refresh_job:
            self.root.after_cancel(self.auto_refresh_job)
            self.auto_refresh_job = None

    def update_yara_match_badge(self):
        """Update YARA match badge in Analysis button"""
        if self.total_yara_matches > 0:
            self.btn_analysis.configure(text=f"Analysis ({self.total_yara_matches})")
        else:
            self.btn_analysis.configure(text="Analysis")

    def get_child_pids_recursive(self, parent_pid):
        """Get all child PIDs recursively"""
        child_pids = set()
        try:
            import psutil
            parent = psutil.Process(parent_pid)
            children = parent.children(recursive=True)
            for child in children:
                child_pids.add(child.pid)
        except:
            pass
        return child_pids

    # ==================== NETWORK HANDLERS (delegated) ====================

    def toggle_network_monitoring(self):
        """Toggle network monitoring"""
        self.network_handlers.toggle_network_monitoring()

    def refresh_network_list(self):
        """Refresh network list"""
        self.network_handlers.refresh_network_list()

    def show_network_context_menu(self, event):
        """Show network context menu"""
        self.network_handlers.show_network_context_menu(event)

    def copy_network_cell(self, column_index):
        """Copy network cell"""
        self.network_handlers.copy_network_cell(column_index)

    def copy_network_row(self):
        """Copy network row"""
        self.network_handlers.copy_network_row()

    def add_network_ioc_to_case(self, field_type):
        """Add network IOC to case"""
        self.network_handlers.add_network_ioc_to_case(field_type)

    def add_live_event_iocs_to_case(self, events_tree):
        """Add live event IOCs to case"""
        self.network_handlers.add_live_event_iocs_to_case(events_tree)

    def on_new_connection_detected(self, conn_info):
        """Callback for new connection detection"""
        self.network_handlers.on_new_connection_detected(conn_info)

    # ==================== FILE HANDLERS (delegated) ====================

    def view_file_strings(self, file_path, file_name):
        """View file strings"""
        self.file_handlers.view_file_strings(file_path, file_name)

    def view_file_hex(self, file_path, file_name):
        """View file in hex format"""
        self.file_handlers.view_file_hex(file_path, file_name)

    def view_file_text(self, file_path, file_name):
        """View file as text"""
        self.file_handlers.view_file_text(file_path, file_name)

    def execute_file(self, file_path, file_name, suspended=False):
        """Execute file"""
        self.file_handlers.execute_file(file_path, file_name, suspended)

    # ==================== YARA RULE HANDLERS ====================

    def refresh_yara_rules_list(self):
        """Refresh YARA rules list"""
        if "yara_rules" in self.tab_objects:
            self.tab_objects["yara_rules"].refresh_rules_list()

    def add_yara_rule_dialog(self):
        """Show add YARA rule dialog"""
        YaraAddDialog(self)

    def import_yara_rule_file(self):
        """Import YARA rule from file"""
        file_path = filedialog.askopenfilename(
            title="Import YARA Rule",
            filetypes=[("YARA files", "*.yar *.yara"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                rule_name = os.path.basename(file_path)
                self.yara_rule_manager.save_rule(rule_name, content)
                self.refresh_yara_rules_list()
                messagebox.showinfo("Success", f"Rule '{rule_name}' imported successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import rule: {str(e)}")

    def view_yara_rule(self, rule):
        """View YARA rule"""
        YaraViewDialog(self, rule)

    def edit_yara_rule(self, rule):
        """Edit YARA rule"""
        YaraEditDialog(self, rule)

    def delete_yara_rule(self, rule):
        """Delete YARA rule"""
        if messagebox.askyesno("Confirm Delete", f"Delete rule '{rule['name']}'?"):
            try:
                self.yara_rule_manager.delete_rule(rule['name'])
                self.refresh_yara_rules_list()
                messagebox.showinfo("Success", "Rule deleted successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete rule: {str(e)}")

    # ==================== PROGRESS WINDOW ====================

    def show_progress_window(self, title="Processing"):
        """Show progress window"""
        self.progress_window = ProgressDialog(self, title)
        return self.progress_window

    def update_progress(self, current, total, message=""):
        """Update progress window"""
        if self.progress_window:
            self.progress_window.update_progress(current, total, message)

    def close_progress_window(self):
        """Close progress window"""
        if self.progress_window:
            self.progress_window.close()
            self.progress_window = None


# Entry point for running the modular version
if __name__ == "__main__":
    print("Starting MAD (Modular Architecture)...")
    print("Note: Original MAD.py is still available as fallback")
    app = ForensicAnalysisGUI()
    app.run()
