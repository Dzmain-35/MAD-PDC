"""
YARA Rules View for MAD - YARA rule management interface.
Extracted from MAD.py create_yara_rules_tab() and related methods.
"""

import os
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typography import Fonts
from views.base_view import BaseView


class YaraRulesView(BaseView):
    """YARA rules management view.

    Provides a treeview listing of all YARA rule files with sorting,
    context menus, and CRUD dialogs (add, view, edit, delete, import).
    """

    def __init__(self, parent, app, colors):
        super().__init__(parent, app, colors)
        # View-local state
        self.yara_rules_tree = None
        self.yara_sort_column = "name"
        self.yara_sort_reverse = False
        self.yara_rules_count_label = None
        self.yara_context_menu = None
        self.btn_add_yara_rule = None
        self.btn_edit_yara_rule = None
        self._build()

    @property
    def yara_rule_manager(self):
        return self.app.yara_rule_manager

    def _build(self):
        """Build the YARA Rules Management UI."""
        frame = self.frame

        # Header
        header_frame = ctk.CTkFrame(frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=20)

        title = ctk.CTkLabel(header_frame, text="YARA Rules Management",
                             font=Fonts.header_subsection,
                             text_color="white")
        title.pack(side="left")

        # Action buttons
        btn_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        btn_frame.pack(side="right")

        _action_font = Fonts.label_large if self.is_large_screen else Fonts.label
        self.btn_add_yara_rule = ctk.CTkButton(btn_frame, text="+ Add Rule",
                                     command=self.add_yara_rule_dialog,
                                     fg_color=self.colors["red"],
                                     hover_color=self.colors["red_dark"],
                                     font=_action_font)
        # Only show Add Rule button if rule creation is enabled in settings
        if self.settings_manager.get("yara.enable_rule_creation", True):
            self.btn_add_yara_rule.pack(side="left", padx=5)

        btn_import_rule = ctk.CTkButton(btn_frame, text="Import from File",
                                        command=self.import_yara_rule_file,
                                        fg_color=self.colors["navy"],
                                        hover_color=self.colors["dark_blue"],
                                        font=_action_font)
        btn_import_rule.pack(side="left", padx=5)

        btn_refresh = ctk.CTkButton(btn_frame, text="Refresh",
                                    command=self.refresh_yara_rules_list,
                                    fg_color=self.colors["navy"],
                                    hover_color=self.colors["dark_blue"],
                                    font=_action_font)
        btn_refresh.pack(side="left", padx=5)

        # Info bar
        info_frame = ctk.CTkFrame(frame, fg_color=self.colors["navy"], height=50)
        info_frame.pack(fill="x", padx=20, pady=(0, 10))
        info_frame.pack_propagate(False)

        self.yara_rules_count_label = ctk.CTkLabel(info_frame,
                                                    text="Total Rules: 0",
                                                    font=Fonts.label_large,
                                                    text_color="white")
        self.yara_rules_count_label.pack(side="left", padx=20, pady=10)

        path_label = ctk.CTkLabel(info_frame,
                                  text=f"Location: {self.case_manager.yara_rules_path}",
                                  font=Fonts.label,
                                  text_color="#cccccc")
        path_label.pack(side="left", padx=20, pady=10)

        # Rules list container with scrollbar
        list_container = ctk.CTkFrame(frame, fg_color=self.colors["navy"])
        list_container.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Create Treeview for efficient display of many rules
        # Style configuration for dark theme
        style = ttk.Style()
        style.theme_use('default')
        _yara_font_size = 14 if self.is_large_screen else 11
        _yara_heading_size = 15 if self.is_large_screen else 12
        _yara_row_height = 32 if self.is_large_screen else 24

        style.configure("Yara.Treeview",
                        background="#1a2332",
                        foreground="white",
                        fieldbackground="#1a2332",
                        borderwidth=0,
                        font=('Segoe UI', _yara_font_size),
                        rowheight=_yara_row_height)
        style.configure("Yara.Treeview.Heading",
                        background="#0d1520",
                        foreground="white",
                        borderwidth=0,
                        font=('Segoe UI', _yara_heading_size, 'bold'))
        style.map('Yara.Treeview',
                  background=[('selected', '#991b1b')])

        # Create treeview with scrollbar
        tree_frame = tk.Frame(list_container, bg="#1a2332")
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
        self.yara_rules_tree.heading("name", text="Rule Filename \u25bc", anchor="w",
                                     command=lambda: self.sort_yara_tree("name"))
        self.yara_rules_tree.heading("size", text="Size (bytes)", anchor="center",
                                     command=lambda: self.sort_yara_tree("size"))
        self.yara_rules_tree.heading("modified", text="Last Modified", anchor="center",
                                     command=lambda: self.sort_yara_tree("modified"))

        self.yara_rules_tree.column("name", width=300, anchor="w")
        self.yara_rules_tree.column("size", width=120, anchor="center")
        self.yara_rules_tree.column("modified", width=200, anchor="center")

        self.yara_rules_tree.pack(fill="both", expand=True)

        # Context menu for rule actions (Edit option added dynamically based on settings)
        self.yara_context_menu = tk.Menu(self.root, tearoff=0, bg="#0d1520", fg="white",
                                         activebackground="#991b1b", activeforeground="white")

        # Bind right-click to show context menu (built dynamically)
        self.yara_rules_tree.bind("<Button-3>", self.show_yara_context_menu)

        # Bind double-click to view
        self.yara_rules_tree.bind("<Double-1>", lambda e: self.view_selected_yara_rule())

        # Action buttons below the table
        action_frame = ctk.CTkFrame(frame, fg_color="transparent")
        action_frame.pack(fill="x", padx=20, pady=10)

        btn_view = ctk.CTkButton(action_frame, text="View",
                                 command=self.view_selected_yara_rule,
                                 fg_color=self.colors["navy"],
                                 hover_color=self.colors["dark_blue"],
                                 font=Fonts.label_large,
                                 width=100)
        btn_view.pack(side="left", padx=5)

        self.btn_edit_yara_rule = ctk.CTkButton(action_frame, text="Edit",
                                 command=self.edit_selected_yara_rule,
                                 fg_color=self.colors["navy"],
                                 hover_color=self.colors["dark_blue"],
                                 font=Fonts.label_large,
                                 width=100)
        # Only show Edit button if rule creation is enabled
        if self.settings_manager.get("yara.enable_rule_creation", True):
            self.btn_edit_yara_rule.pack(side="left", padx=5)

        btn_delete = ctk.CTkButton(action_frame, text="Delete",
                                   command=self.delete_selected_yara_rule,
                                   fg_color=self.colors["red"],
                                   hover_color=self.colors["red_dark"],
                                   font=Fonts.label_large,
                                   width=100)
        btn_delete.pack(side="left", padx=5)

        # Initialize sort state
        self.yara_sort_column = "name"
        self.yara_sort_reverse = False

    def on_activate(self):
        """Refresh the rules list when the tab becomes visible."""
        self.refresh_yara_rules_list()

    def apply_creation_setting(self, enabled):
        """Show or hide the Add and Edit buttons based on the rule creation setting.

        Called from SettingsView when the yara.enable_rule_creation setting changes.

        Args:
            enabled: True to show the Add/Edit buttons, False to hide them.
        """
        if self.btn_add_yara_rule:
            if enabled:
                self.btn_add_yara_rule.pack(side="left", padx=5)
            else:
                self.btn_add_yara_rule.pack_forget()
        if self.btn_edit_yara_rule:
            if enabled:
                self.btn_edit_yara_rule.pack(side="left", padx=5)
            else:
                self.btn_edit_yara_rule.pack_forget()

    def sort_yara_tree(self, column):
        """Sort treeview by column."""
        # Toggle sort direction if clicking same column
        if self.yara_sort_column == column:
            self.yara_sort_reverse = not self.yara_sort_reverse
        else:
            self.yara_sort_column = column
            self.yara_sort_reverse = False

        # Get all items
        items = [(self.yara_rules_tree.item(item, "values"), item)
                 for item in self.yara_rules_tree.get_children("")]

        # Determine sort key based on column
        if column == "name":
            col_idx = 0
            key_func = lambda x: x[0][col_idx].lower()
        elif column == "size":
            col_idx = 1
            key_func = lambda x: int(x[0][col_idx].replace(",", "")) if x[0][col_idx] else 0
        elif column == "modified":
            col_idx = 2
            key_func = lambda x: x[0][col_idx]

        # Sort items
        items.sort(key=key_func, reverse=self.yara_sort_reverse)

        # Rearrange items in treeview
        for idx, (values, item) in enumerate(items):
            self.yara_rules_tree.move(item, "", idx)

        # Update column headers with sort indicator
        for col in ["name", "size", "modified"]:
            header_text = {
                "name": "Rule Filename",
                "size": "Size (bytes)",
                "modified": "Last Modified"
            }[col]

            if col == column:
                arrow = " \u25bc" if self.yara_sort_reverse else " \u25b2"
                header_text += arrow

            self.yara_rules_tree.heading(col, text=header_text)

    def refresh_yara_rules_list(self):
        """Refresh the list of YARA rules - optimized for large lists."""
        # Clear existing items
        for item in self.yara_rules_tree.get_children():
            self.yara_rules_tree.delete(item)

        # Get list of rules
        rules = self.yara_rule_manager.list_rules()

        # Update count
        self.yara_rules_count_label.configure(text=f"Total Rules: {len(rules)}")

        if not rules:
            # Insert a message item
            self.yara_rules_tree.insert("", "end", values=("No YARA rules found", "", ""))
            return

        # Insert all rules into treeview (very fast even with 100+ rules)
        for rule in rules:
            self.yara_rules_tree.insert(
                "",
                "end",
                values=(
                    rule["name"],
                    f"{rule['size']:,}",
                    rule['modified'].strftime('%Y-%m-%d %H:%M:%S')
                ),
                tags=(rule["name"],)  # Store rule name in tags for easy retrieval
            )

    def show_yara_context_menu(self, event):
        """Show context menu on right-click (built dynamically based on settings)."""
        # Select the item under cursor
        item = self.yara_rules_tree.identify_row(event.y)
        if item:
            self.yara_rules_tree.selection_set(item)
            # Rebuild menu dynamically based on settings
            self.yara_context_menu.delete(0, tk.END)
            self.yara_context_menu.add_command(label="View Rule", command=self.view_selected_yara_rule)
            if self.settings_manager.get("yara.enable_rule_creation", True):
                self.yara_context_menu.add_command(label="Edit Rule", command=self.edit_selected_yara_rule)
            self.yara_context_menu.add_separator()
            self.yara_context_menu.add_command(label="Delete Rule", command=self.delete_selected_yara_rule)
            self.yara_context_menu.post(event.x_root, event.y_root)

    def get_selected_yara_rule(self):
        """Get the currently selected rule from the tree."""
        selection = self.yara_rules_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a rule first")
            return None

        item = selection[0]
        values = self.yara_rules_tree.item(item, "values")
        if not values or values[0] == "No YARA rules found":
            return None

        # Return rule dict with the necessary info
        return {
            "name": values[0],
            "size": int(values[1].replace(",", "")),
            "modified": None  # Not needed for operations
        }

    def view_selected_yara_rule(self):
        """View the selected rule."""
        rule = self.get_selected_yara_rule()
        if rule:
            self.view_yara_rule(rule)

    def edit_selected_yara_rule(self):
        """Edit the selected rule."""
        rule = self.get_selected_yara_rule()
        if rule:
            self.edit_yara_rule(rule)

    def delete_selected_yara_rule(self):
        """Delete the selected rule."""
        rule = self.get_selected_yara_rule()
        if rule:
            self.delete_yara_rule(rule)

    def add_yara_rule_dialog(self):
        """Show dialog to add a new YARA rule."""
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Add YARA Rule")
        dialog.geometry("800x600")
        dialog.transient(self.root)
        dialog.grab_set()

        # Header
        header = ctk.CTkLabel(dialog, text="Create New YARA Rule",
                              font=Fonts.header_subsection)
        header.pack(pady=20)

        # Rule name input
        name_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        name_frame.pack(fill="x", padx=20, pady=10)

        name_label = ctk.CTkLabel(name_frame, text="Rule Filename:",
                                  font=Fonts.label_large)
        name_label.pack(side="left", padx=10)

        name_entry = ctk.CTkEntry(name_frame, placeholder_text="example.yara",
                                  font=Fonts.label_large, width=300)
        name_entry.pack(side="left", padx=10)

        # Rule content text area
        content_label = ctk.CTkLabel(dialog, text="Rule Content:",
                                     font=Fonts.label_large)
        content_label.pack(anchor="w", padx=30, pady=(10, 5))

        content_frame = ctk.CTkFrame(dialog)
        content_frame.pack(fill="both", expand=True, padx=20, pady=10)

        content_text = ctk.CTkTextbox(content_frame, font=("Courier", 12))
        content_text.pack(fill="both", expand=True)

        # Add example template
        example_rule = """rule Example_Rule
{
    meta:
        author = "Your Name"
        description = "Description of what this rule detects"

    strings:
        $string1 = "suspicious string" ascii wide
        $string2 = { 6A 40 68 00 30 00 00 }

    condition:
        any of them
}"""
        content_text.insert("1.0", example_rule)

        # Validation status
        status_label = ctk.CTkLabel(dialog, text="",
                                    font=Fonts.label,
                                    text_color="yellow")
        status_label.pack(pady=5)

        # Buttons
        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(pady=20)

        def validate_and_add():
            rule_name = name_entry.get().strip()
            rule_content = content_text.get("1.0", "end-1c").strip()

            if not rule_name:
                status_label.configure(text="Please enter a rule filename",
                                       text_color="red")
                return

            if not rule_content:
                status_label.configure(text="Please enter rule content",
                                       text_color="red")
                return

            # Validate rule syntax
            is_valid, error_msg = self.yara_rule_manager.validate_yara_rule(rule_content)
            if not is_valid:
                status_label.configure(text=f"Validation failed: {error_msg}",
                                       text_color="red")
                return

            # Add the rule
            success, message = self.yara_rule_manager.add_rule_from_content(rule_name, rule_content)
            if success:
                messagebox.showinfo("Success", message)
                dialog.destroy()
                self.refresh_yara_rules_list()
                # Reload YARA rules in case manager
                self.case_manager.load_yara_rules()
            else:
                status_label.configure(text=f"Error: {message}",
                                       text_color="red")

        btn_validate = ctk.CTkButton(btn_frame, text="Validate",
                                     command=lambda: self.validate_rule_content(content_text, status_label),
                                     fg_color=self.colors["navy"],
                                     hover_color=self.colors["dark_blue"],
                                     font=Fonts.label_large)
        btn_validate.pack(side="left", padx=5)

        btn_add = ctk.CTkButton(btn_frame, text="Add Rule",
                                command=validate_and_add,
                                fg_color=self.colors["red"],
                                hover_color=self.colors["red_dark"],
                                font=Fonts.label_large)
        btn_add.pack(side="left", padx=5)

        btn_cancel = ctk.CTkButton(btn_frame, text="Cancel",
                                   command=dialog.destroy,
                                   fg_color="gray",
                                   font=Fonts.label_large)
        btn_cancel.pack(side="left", padx=5)

    def validate_rule_content(self, text_widget, status_label):
        """Validate YARA rule content."""
        rule_content = text_widget.get("1.0", "end-1c").strip()
        is_valid, error_msg = self.yara_rule_manager.validate_yara_rule(rule_content)

        if is_valid:
            status_label.configure(text="\u2713 Rule syntax is valid",
                                   text_color="green")
        else:
            status_label.configure(text=f"\u2717 {error_msg}",
                                   text_color="red")

    def import_yara_rule_file(self):
        """Import a YARA rule from a file."""
        file_path = filedialog.askopenfilename(
            title="Select YARA Rule File",
            filetypes=[("YARA Rules", "*.yara *.yar"), ("All Files", "*.*")]
        )

        if not file_path:
            return

        success, message = self.yara_rule_manager.add_rule_from_file(file_path)
        if success:
            messagebox.showinfo("Success", message)
            self.refresh_yara_rules_list()
            # Reload YARA rules in case manager
            self.case_manager.load_yara_rules()
        else:
            messagebox.showerror("Error", message)

    def view_yara_rule(self, rule):
        """View a YARA rule in a read-only dialog."""
        success, content = self.yara_rule_manager.get_rule_content(rule["name"])
        if not success:
            messagebox.showerror("Error", content)
            return

        dialog = ctk.CTkToplevel(self.root)
        dialog.title(f"View Rule: {rule['name']}")
        dialog.geometry("800x600")
        dialog.transient(self.root)

        # Header
        header = ctk.CTkLabel(dialog, text=rule["name"],
                              font=Fonts.header_subsection)
        header.pack(pady=20)

        # Content display
        content_frame = ctk.CTkFrame(dialog)
        content_frame.pack(fill="both", expand=True, padx=20, pady=10)

        content_text = ctk.CTkTextbox(content_frame, font=("Courier", 12))
        content_text.pack(fill="both", expand=True)
        content_text.insert("1.0", content)
        content_text.configure(state="disabled")

        # Close button
        btn_close = ctk.CTkButton(dialog, text="Close",
                                  command=dialog.destroy,
                                  font=Fonts.label_large)
        btn_close.pack(pady=20)

    def edit_yara_rule(self, rule):
        """Edit an existing YARA rule."""
        success, content = self.yara_rule_manager.get_rule_content(rule["name"])
        if not success:
            messagebox.showerror("Error", content)
            return

        dialog = ctk.CTkToplevel(self.root)
        dialog.title(f"Edit Rule: {rule['name']}")
        dialog.geometry("800x600")
        dialog.transient(self.root)
        dialog.grab_set()

        # Header
        header = ctk.CTkLabel(dialog, text=f"Editing: {rule['name']}",
                              font=Fonts.header_subsection)
        header.pack(pady=20)

        # Content editor
        content_frame = ctk.CTkFrame(dialog)
        content_frame.pack(fill="both", expand=True, padx=20, pady=10)

        content_text = ctk.CTkTextbox(content_frame, font=("Courier", 12))
        content_text.pack(fill="both", expand=True)
        content_text.insert("1.0", content)

        # Validation status
        status_label = ctk.CTkLabel(dialog, text="",
                                    font=Fonts.label)
        status_label.pack(pady=5)

        # Buttons
        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(pady=20)

        def save_changes():
            new_content = content_text.get("1.0", "end-1c").strip()

            # Validate
            is_valid, error_msg = self.yara_rule_manager.validate_yara_rule(new_content)
            if not is_valid:
                status_label.configure(text=f"Validation failed: {error_msg}",
                                       text_color="red")
                return

            # Update with backup setting from settings
            create_backup = self.settings_manager.get("yara.create_backups_on_update", True)
            success, message = self.yara_rule_manager.update_rule(rule["name"], new_content, create_backup=create_backup)
            if success:
                messagebox.showinfo("Success", message)
                dialog.destroy()
                self.refresh_yara_rules_list()
                # Reload YARA rules in case manager
                self.case_manager.load_yara_rules()
            else:
                status_label.configure(text=f"Error: {message}",
                                       text_color="red")

        btn_validate = ctk.CTkButton(btn_frame, text="Validate",
                                     command=lambda: self.validate_rule_content(content_text, status_label),
                                     fg_color=self.colors["navy"],
                                     font=Fonts.label_large)
        btn_validate.pack(side="left", padx=5)

        btn_save = ctk.CTkButton(btn_frame, text="Save Changes",
                                 command=save_changes,
                                 fg_color=self.colors["red"],
                                 hover_color=self.colors["red_dark"],
                                 font=Fonts.label_large)
        btn_save.pack(side="left", padx=5)

        btn_cancel = ctk.CTkButton(btn_frame, text="Cancel",
                                   command=dialog.destroy,
                                   fg_color="gray",
                                   font=Fonts.label_large)
        btn_cancel.pack(side="left", padx=5)

    def delete_yara_rule(self, rule):
        """Delete a YARA rule."""
        # Check if backups are enabled in settings
        create_backup = self.settings_manager.get("yara.create_backups_on_delete", True)

        backup_msg = "\n\nA backup will be created automatically." if create_backup else ""
        result = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete '{rule['name']}'?{backup_msg}"
        )

        if not result:
            return

        success, message = self.yara_rule_manager.delete_rule(rule["name"], create_backup=create_backup)
        if success:
            messagebox.showinfo("Success", message)
            self.refresh_yara_rules_list()
            # Reload YARA rules in case manager
            self.case_manager.load_yara_rules()
        else:
            messagebox.showerror("Error", message)
