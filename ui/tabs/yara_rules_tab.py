"""
YARA Rules Tab
Tab for managing YARA detection rules.
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import TYPE_CHECKING

from typography import Fonts
from ui.theme import Theme
from .base_tab import BaseTab

if TYPE_CHECKING:
    from ui.app import ForensicAnalysisGUI


class YaraRulesTab(BaseTab):
    """Tab for YARA rules management"""

    def __init__(self, app: 'ForensicAnalysisGUI', parent: ctk.CTkFrame):
        super().__init__(app, parent)
        self.yara_rules_tree = None
        self.yara_rules_count_label = None
        self.yara_context_menu = None
        self.yara_sort_column = "name"
        self.yara_sort_reverse = False

    def create(self) -> ctk.CTkFrame:
        """Create the YARA Rules Management tab"""
        self.frame = ctk.CTkFrame(self.parent, fg_color=self.colors["dark_blue"])

        # Header
        header_frame = ctk.CTkFrame(self.frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=20)

        title = ctk.CTkLabel(
            header_frame, text="YARA Rules Management",
            font=Fonts.header_subsection,
            text_color="white"
        )
        title.pack(side="left")

        # Action buttons
        btn_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        btn_frame.pack(side="right")

        btn_add_rule = ctk.CTkButton(
            btn_frame, text="+ Add Rule",
            command=self.app.add_yara_rule_dialog,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            font=Fonts.label_large
        )
        btn_add_rule.pack(side="left", padx=5)

        btn_import_rule = ctk.CTkButton(
            btn_frame, text="Import from File",
            command=self.app.import_yara_rule_file,
            fg_color=self.colors["navy"],
            hover_color=self.colors["dark_blue"],
            font=Fonts.label_large
        )
        btn_import_rule.pack(side="left", padx=5)

        btn_refresh = ctk.CTkButton(
            btn_frame, text="Refresh",
            command=self.refresh_rules_list,
            fg_color=self.colors["navy"],
            hover_color=self.colors["dark_blue"],
            font=Fonts.label_large
        )
        btn_refresh.pack(side="left", padx=5)

        # Info bar
        info_frame = ctk.CTkFrame(self.frame, fg_color=self.colors["navy"], height=50)
        info_frame.pack(fill="x", padx=20, pady=(0, 10))
        info_frame.pack_propagate(False)

        self.yara_rules_count_label = ctk.CTkLabel(
            info_frame,
            text="Total Rules: 0",
            font=Fonts.label_large,
            text_color="white"
        )
        self.yara_rules_count_label.pack(side="left", padx=20, pady=10)

        path_label = ctk.CTkLabel(
            info_frame,
            text=f"Location: {self.app.case_manager.yara_rules_path}",
            font=Fonts.label,
            text_color="#cccccc"
        )
        path_label.pack(side="left", padx=20, pady=10)

        # Rules list container
        list_container = ctk.CTkFrame(self.frame, fg_color=self.colors["navy"])
        list_container.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Create treeview
        self._create_rules_tree(list_container)

        # Context menu
        self._create_context_menu()

        # Action buttons below the table
        action_frame = ctk.CTkFrame(self.frame, fg_color="transparent")
        action_frame.pack(fill="x", padx=20, pady=10)

        btn_view = ctk.CTkButton(
            action_frame, text="View",
            command=self.view_selected_rule,
            fg_color=self.colors["navy"],
            hover_color=self.colors["dark_blue"],
            font=Fonts.label_large,
            width=100
        )
        btn_view.pack(side="left", padx=5)

        btn_edit = ctk.CTkButton(
            action_frame, text="Edit",
            command=self.edit_selected_rule,
            fg_color=self.colors["navy"],
            hover_color=self.colors["dark_blue"],
            font=Fonts.label_large,
            width=100
        )
        btn_edit.pack(side="left", padx=5)

        btn_delete = ctk.CTkButton(
            action_frame, text="Delete",
            command=self.delete_selected_rule,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
            font=Fonts.label_large,
            width=100
        )
        btn_delete.pack(side="left", padx=5)

        # Store references in app for backward compatibility
        self.app.yara_rules_tree = self.yara_rules_tree
        self.app.yara_rules_count_label = self.yara_rules_count_label
        self.app.yara_context_menu = self.yara_context_menu
        self.app.yara_sort_column = self.yara_sort_column
        self.app.yara_sort_reverse = self.yara_sort_reverse

        return self.frame

    def _create_rules_tree(self, parent):
        """Create the rules treeview"""
        # Style configuration
        style = ttk.Style()
        style.theme_use('default')
        style.configure("Yara.Treeview",
                        background="#1a2332",
                        foreground="white",
                        fieldbackground="#1a2332",
                        borderwidth=0,
                        font=('Segoe UI', 11))
        style.configure("Yara.Treeview.Heading",
                        background="#0d1520",
                        foreground="white",
                        borderwidth=0,
                        font=('Segoe UI', 12, 'bold'))
        style.map('Yara.Treeview',
                  background=[('selected', '#991b1b')])

        # Tree frame
        tree_frame = tk.Frame(parent, bg="#1a2332")
        tree_frame.pack(fill="both", expand=True, padx=2, pady=2)

        # Scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        vsb.pack(side="right", fill="y")

        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")
        hsb.pack(side="bottom", fill="x")

        # Treeview
        self.yara_rules_tree = ttk.Treeview(
            tree_frame,
            columns=("name", "size", "modified"),
            show="headings",
            style="Yara.Treeview",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
            selectmode="browse"
        )

        vsb.config(command=self.yara_rules_tree.yview)
        hsb.config(command=self.yara_rules_tree.xview)

        # Configure columns with sorting
        self.yara_rules_tree.heading("name", text="Rule Filename ▼", anchor="w",
                                      command=lambda: self.sort_tree("name"))
        self.yara_rules_tree.heading("size", text="Size (bytes)", anchor="center",
                                      command=lambda: self.sort_tree("size"))
        self.yara_rules_tree.heading("modified", text="Last Modified", anchor="center",
                                      command=lambda: self.sort_tree("modified"))

        self.yara_rules_tree.column("name", width=300, anchor="w")
        self.yara_rules_tree.column("size", width=120, anchor="center")
        self.yara_rules_tree.column("modified", width=200, anchor="center")

        self.yara_rules_tree.pack(fill="both", expand=True)

        # Bind events
        self.yara_rules_tree.bind("<Button-3>", self._show_context_menu)
        self.yara_rules_tree.bind("<Double-1>", lambda e: self.view_selected_rule())

    def _create_context_menu(self):
        """Create context menu"""
        menu_config = Theme.get_menu_config()
        self.yara_context_menu = tk.Menu(self.app.root, tearoff=0, **menu_config)
        self.yara_context_menu.add_command(label="View Rule", command=self.view_selected_rule)
        self.yara_context_menu.add_command(label="Edit Rule", command=self.edit_selected_rule)
        self.yara_context_menu.add_separator()
        self.yara_context_menu.add_command(label="Delete Rule", command=self.delete_selected_rule)

    def _show_context_menu(self, event):
        """Show context menu on right-click"""
        item = self.yara_rules_tree.identify_row(event.y)
        if item:
            self.yara_rules_tree.selection_set(item)
            self.yara_context_menu.post(event.x_root, event.y_root)

    def sort_tree(self, column):
        """Sort treeview by column"""
        if self.yara_sort_column == column:
            self.yara_sort_reverse = not self.yara_sort_reverse
        else:
            self.yara_sort_column = column
            self.yara_sort_reverse = False

        # Update app references
        self.app.yara_sort_column = self.yara_sort_column
        self.app.yara_sort_reverse = self.yara_sort_reverse

        items = [(self.yara_rules_tree.item(item, "values"), item)
                 for item in self.yara_rules_tree.get_children("")]

        if column == "name":
            key_func = lambda x: x[0][0].lower()
        elif column == "size":
            key_func = lambda x: int(x[0][1].replace(",", "")) if x[0][1] else 0
        elif column == "modified":
            key_func = lambda x: x[0][2]
        else:
            return

        items.sort(key=key_func, reverse=self.yara_sort_reverse)

        for idx, (values, item) in enumerate(items):
            self.yara_rules_tree.move(item, "", idx)

        # Update headers
        headers = {
            "name": "Rule Filename",
            "size": "Size (bytes)",
            "modified": "Last Modified"
        }
        for col, text in headers.items():
            if col == column:
                arrow = " ▼" if self.yara_sort_reverse else " ▲"
                text += arrow
            self.yara_rules_tree.heading(col, text=text)

    def refresh_rules_list(self):
        """Refresh the list of YARA rules"""
        for item in self.yara_rules_tree.get_children():
            self.yara_rules_tree.delete(item)

        rules = self.app.yara_rule_manager.list_rules()
        self.yara_rules_count_label.configure(text=f"Total Rules: {len(rules)}")

        if not rules:
            self.yara_rules_tree.insert("", "end", values=("No YARA rules found", "", ""))
            return

        for rule in rules:
            self.yara_rules_tree.insert(
                "",
                "end",
                values=(
                    rule["name"],
                    f"{rule['size']:,}",
                    rule['modified'].strftime('%Y-%m-%d %H:%M:%S')
                ),
                tags=(rule["name"],)
            )

    def get_selected_rule(self):
        """Get the currently selected rule"""
        selection = self.yara_rules_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a rule first")
            return None

        item = selection[0]
        values = self.yara_rules_tree.item(item, "values")
        if not values or values[0] == "No YARA rules found":
            return None

        return {
            "name": values[0],
            "size": int(values[1].replace(",", "")),
            "modified": None
        }

    def view_selected_rule(self):
        """View the selected rule"""
        rule = self.get_selected_rule()
        if rule:
            self.app.view_yara_rule(rule)

    def edit_selected_rule(self):
        """Edit the selected rule"""
        rule = self.get_selected_rule()
        if rule:
            self.app.edit_yara_rule(rule)

    def delete_selected_rule(self):
        """Delete the selected rule"""
        rule = self.get_selected_rule()
        if rule:
            self.app.delete_yara_rule(rule)

    def on_show(self):
        """Called when tab is shown - refresh the rules list"""
        self.refresh_rules_list()
