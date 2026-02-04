"""
Network Handlers
Business logic for network monitoring and analysis operations.
"""

import socket
import threading
from tkinter import messagebox
from typing import TYPE_CHECKING, Optional, Dict, Any, List

import customtkinter as ctk
import tkinter as tk

from typography import Fonts

if TYPE_CHECKING:
    from ui.app import ForensicAnalysisGUI


class NetworkHandlers:
    """Handler class for network monitoring business logic"""

    def __init__(self, app: 'ForensicAnalysisGUI'):
        self.app = app
        self.hostname_cache: Dict[str, str] = {}

    @property
    def network_monitor(self):
        return self.app.network_monitor

    @property
    def network_tree(self):
        return self.app.network_tree

    @property
    def case_manager(self):
        return self.app.case_manager

    @property
    def current_case(self):
        return self.app.current_case

    # ==================== NETWORK MONITORING ====================
    def toggle_network_monitoring(self):
        """Toggle network monitoring on/off"""
        if not self.app.network_monitor_active:
            self.network_monitor.start_monitoring()
            self.app.network_monitor_active = True
            self.app.btn_toggle_network_monitor.configure(text="Stop Monitoring")
            self.start_network_auto_refresh()
        else:
            self.network_monitor.stop_monitoring()
            self.app.network_monitor_active = False
            self.app.btn_toggle_network_monitor.configure(text="Start Monitoring")

    def start_network_auto_refresh(self):
        """Start auto-refreshing network connections list"""
        if self.app.network_monitor_active:
            self.refresh_network_list()
            self.app.root.after(
                self.app.auto_refresh_interval,
                self.start_network_auto_refresh
            )

    # ==================== NETWORK LIST MANAGEMENT ====================
    def refresh_network_list(self):
        """Refresh network connections list"""
        # Clear existing
        for item in self.network_tree.get_children():
            self.network_tree.delete(item)

        # Get connections
        connections = self.network_monitor.get_all_connections()

        for conn in connections:
            local_addr = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
            remote_addr = f"{conn.get('remote_ip', '')}:{conn.get('remote_port', '')}"

            # Resolve hostname for remote IP
            remote_ip = conn.get('remote_ip', '')
            hostname = self.resolve_hostname(remote_ip) if remote_ip else '-'

            suspicious_text = "Yes" if conn.get('suspicious', False) else "No"
            tags = ('suspicious',) if conn.get('suspicious', False) else ()

            self.network_tree.insert(
                "", "end",
                values=(
                    conn.get('type', ''),
                    local_addr,
                    remote_addr,
                    hostname,
                    conn.get('status', ''),
                    conn.get('process_name', 'Unknown'),
                    suspicious_text
                ),
                tags=tags
            )

        # Update stats
        if self.app.network_monitor_active:
            summary = self.network_monitor.get_connection_summary()
            stats_text = f"""Network Statistics:
Active: {summary['active_connections']} | Total: {summary['total_connections']} | Suspicious: {summary['suspicious_connections']}
Unique IPs: {summary['unique_remote_ips']} | Unique Ports: {summary['unique_local_ports']}"""
            self.app.network_stats_label.configure(text=stats_text)

    def resolve_hostname(self, ip_address: str) -> str:
        """Resolve IP address to hostname with caching"""
        # Check cache first
        if ip_address in self.hostname_cache:
            return self.hostname_cache[ip_address]

        # Skip resolution for local/private IPs
        if ip_address in ['', '0.0.0.0', '127.0.0.1', 'localhost', '*']:
            self.hostname_cache[ip_address] = '-'
            return '-'

        # Try to resolve
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            self.hostname_cache[ip_address] = hostname
            return hostname
        except:
            self.hostname_cache[ip_address] = '-'
            return '-'

    # ==================== CONTEXT MENU ACTIONS ====================
    def show_network_context_menu(self, event):
        """Show right-click context menu for network connections"""
        try:
            self.app.network_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.app.network_context_menu.grab_release()

    def copy_network_cell(self, column_index: int):
        """Copy a specific cell from selected network row to clipboard"""
        selection = self.network_tree.selection()
        if not selection:
            return

        try:
            item = self.network_tree.item(selection[0])
            values = item['values']
            if values and len(values) > column_index:
                cell_value = str(values[column_index])
                self.app.root.clipboard_clear()
                self.app.root.clipboard_append(cell_value)
                self.app.root.update()
        except Exception as e:
            print(f"Error copying network cell: {e}")

    def copy_network_row(self):
        """Copy entire row from selected network connection to clipboard"""
        selection = self.network_tree.selection()
        if not selection:
            return

        try:
            item = self.network_tree.item(selection[0])
            values = item['values']
            if values:
                row_text = " | ".join(str(v) for v in values)
                self.app.root.clipboard_clear()
                self.app.root.clipboard_append(row_text)
                self.app.root.update()
        except Exception as e:
            print(f"Error copying network row: {e}")

    # ==================== IOC MANAGEMENT ====================
    def add_network_ioc_to_case(self, field_type: str):
        """Add selected network IOC to current case"""
        if not self.current_case:
            messagebox.showwarning(
                "No Active Case",
                "No active case to add IOC to. Please create or load a case first."
            )
            return

        selection = self.network_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a network connection first.")
            return

        try:
            item = self.network_tree.item(selection[0])
            values = item['values']  # [Type, Local, Remote, Hostname, Status, Process, Suspicious]

            if field_type == "remote_ip" and len(values) > 2:
                # Extract IP from "IP:Port" format in Remote column (index 2)
                remote_addr = str(values[2])
                remote_ip = remote_addr.split(':')[0] if ':' in remote_addr else remote_addr

                if remote_ip and remote_ip != '-':
                    self.case_manager.add_ioc("ips", remote_ip)
                    self.app.refresh_iocs_display()
                    messagebox.showinfo("Success", f"Added IP '{remote_ip}' to case IOCs!")
                else:
                    messagebox.showwarning("Invalid IP", "No valid IP address found in the selected connection.")

            elif field_type == "hostname" and len(values) > 3:
                hostname = str(values[3])
                if hostname and hostname != '-':
                    self.case_manager.add_ioc("domains", hostname)
                    self.app.refresh_iocs_display()
                    messagebox.showinfo("Success", f"Added domain '{hostname}' to case IOCs!")
                else:
                    messagebox.showwarning("Invalid Hostname", "No valid hostname found in the selected connection.")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to add IOC: {str(e)}")

    def add_live_event_iocs_to_case(self, events_tree):
        """Extract and add IOCs from selected live event(s) to current case"""
        if not self.current_case:
            messagebox.showwarning(
                "No Active Case",
                "No active case to add IOCs to. Please create or load a case first."
            )
            return

        selections = events_tree.selection()
        if not selections:
            messagebox.showwarning("No Selection", "Please select one or more live events first.")
            return

        try:
            # Collect all text from selected events to extract IOCs
            all_text = []
            for selection in selections:
                item = events_tree.item(selection)
                values = item['values']  # [time, pid, process, type, operation, path, result]

                # Get path/target field (index 5) which is most likely to contain IOCs
                if len(values) > 5:
                    path = str(values[5])
                    all_text.append(path)

            # Join all text and extract IOCs
            combined_text = " ".join(all_text)
            extracted_iocs = self.case_manager.extract_iocs_from_text(combined_text)

            # Add extracted IOCs to case
            total_added = 0
            for ioc_type in ['urls', 'ips', 'domains']:
                if extracted_iocs.get(ioc_type):
                    for ioc_value in extracted_iocs[ioc_type]:
                        self.case_manager.add_ioc(ioc_type, ioc_value)
                        total_added += 1

            if total_added > 0:
                self.app.refresh_iocs_display()
                ioc_summary = (
                    f"URLs: {len(extracted_iocs.get('urls', []))}, "
                    f"IPs: {len(extracted_iocs.get('ips', []))}, "
                    f"Domains: {len(extracted_iocs.get('domains', []))}"
                )
                messagebox.showinfo(
                    "Success",
                    f"Extracted and added {total_added} IOC(s) to case!\n\n{ioc_summary}"
                )
            else:
                messagebox.showinfo(
                    "No IOCs Found",
                    "No IOCs (URLs, IPs, or domains) were found in the selected event(s)."
                )

        except Exception as e:
            messagebox.showerror("Error", f"Failed to extract IOCs: {str(e)}")

    # ==================== CONNECTION CALLBACKS ====================
    def on_new_connection_detected(self, conn_info: Optional[Dict[str, Any]]):
        """Callback when new network connection is detected"""
        if not conn_info:
            return

        if conn_info.get('suspicious'):
            # Could implement network alerts here
            print(f"Suspicious connection detected: {conn_info}")

    # ==================== UTILITY METHODS ====================
    def get_selected_connection(self) -> Optional[Dict[str, Any]]:
        """Get the currently selected network connection"""
        selection = self.network_tree.selection()
        if not selection:
            return None

        try:
            item = self.network_tree.item(selection[0])
            values = item['values']
            if values:
                return {
                    'type': values[0],
                    'local_addr': values[1],
                    'remote_addr': values[2],
                    'hostname': values[3],
                    'status': values[4],
                    'process': values[5],
                    'suspicious': values[6] == 'Yes'
                }
        except Exception as e:
            print(f"Error getting selected connection: {e}")

        return None

    def filter_connections(self, filter_type: str = "all"):
        """Filter network connections by type"""
        self.refresh_network_list()

        if filter_type == "all":
            return

        # Get all items and filter
        for item in self.network_tree.get_children():
            values = self.network_tree.item(item, 'values')
            if not values:
                continue

            show_item = False

            if filter_type == "suspicious" and values[6] == "Yes":
                show_item = True
            elif filter_type == "tcp" and values[0].upper() == "TCP":
                show_item = True
            elif filter_type == "udp" and values[0].upper() == "UDP":
                show_item = True
            elif filter_type == "established" and values[4] == "ESTABLISHED":
                show_item = True

            if not show_item:
                self.network_tree.delete(item)

    def export_connections(self, file_path: str) -> bool:
        """Export current network connections to file"""
        try:
            connections = self.network_monitor.get_all_connections()

            with open(file_path, 'w') as f:
                f.write("Type,Local Address,Remote Address,Hostname,Status,Process,Suspicious\n")
                for conn in connections:
                    local_addr = f"{conn.get('local_ip', '')}:{conn.get('local_port', '')}"
                    remote_addr = f"{conn.get('remote_ip', '')}:{conn.get('remote_port', '')}"
                    remote_ip = conn.get('remote_ip', '')
                    hostname = self.resolve_hostname(remote_ip) if remote_ip else '-'
                    suspicious = "Yes" if conn.get('suspicious', False) else "No"

                    f.write(f"{conn.get('type', '')},{local_addr},{remote_addr},{hostname},"
                           f"{conn.get('status', '')},{conn.get('process_name', 'Unknown')},{suspicious}\n")

            return True
        except Exception as e:
            print(f"Error exporting connections: {e}")
            return False
