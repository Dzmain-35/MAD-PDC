"""
YARA Rule Dialogs
Dialogs for adding, editing, and viewing YARA rules.
"""

import customtkinter as ctk
from tkinter import messagebox
from typing import TYPE_CHECKING, Optional, Dict, Any

from typography import Fonts
from ui.theme import Colors

if TYPE_CHECKING:
    from ui.app import ForensicAnalysisGUI


class YaraViewDialog:
    """Dialog for viewing a YARA rule (read-only)"""

    def __init__(self, app: 'ForensicAnalysisGUI', rule: Dict[str, Any]):
        self.app = app
        self.rule = rule
        self.window: Optional[ctk.CTkToplevel] = None
        self._create_window()

    def _create_window(self):
        """Create the view dialog"""
        success, content = self.app.yara_rule_manager.get_rule_content(self.rule["name"])
        if not success:
            messagebox.showerror("Error", content)
            return

        self.window = ctk.CTkToplevel(self.app.root)
        self.window.title(f"View Rule: {self.rule['name']}")
        self.window.geometry("800x600")
        self.window.transient(self.app.root)

        # Header
        header = ctk.CTkLabel(
            self.window, text=self.rule["name"],
            font=Fonts.header_subsection
        )
        header.pack(pady=20)

        # Content display
        content_frame = ctk.CTkFrame(self.window)
        content_frame.pack(fill="both", expand=True, padx=20, pady=10)

        content_text = ctk.CTkTextbox(content_frame, font=("Courier", 12))
        content_text.pack(fill="both", expand=True)
        content_text.insert("1.0", content)
        content_text.configure(state="disabled")

        # Close button
        btn_close = ctk.CTkButton(
            self.window, text="Close",
            command=self.close,
            font=Fonts.label_large
        )
        btn_close.pack(pady=20)

    def close(self):
        """Close the dialog"""
        if self.window:
            self.window.destroy()


class YaraEditDialog:
    """Dialog for editing an existing YARA rule"""

    def __init__(self, app: 'ForensicAnalysisGUI', rule: Dict[str, Any]):
        self.app = app
        self.rule = rule
        self.window: Optional[ctk.CTkToplevel] = None
        self.content_text: Optional[ctk.CTkTextbox] = None
        self.status_label: Optional[ctk.CTkLabel] = None
        self._create_window()

    def _create_window(self):
        """Create the edit dialog"""
        success, content = self.app.yara_rule_manager.get_rule_content(self.rule["name"])
        if not success:
            messagebox.showerror("Error", content)
            return

        self.window = ctk.CTkToplevel(self.app.root)
        self.window.title(f"Edit Rule: {self.rule['name']}")
        self.window.geometry("800x600")
        self.window.transient(self.app.root)
        self.window.grab_set()

        # Header
        header = ctk.CTkLabel(
            self.window, text=f"Editing: {self.rule['name']}",
            font=Fonts.header_subsection
        )
        header.pack(pady=20)

        # Content editor
        content_frame = ctk.CTkFrame(self.window)
        content_frame.pack(fill="both", expand=True, padx=20, pady=10)

        self.content_text = ctk.CTkTextbox(content_frame, font=("Courier", 12))
        self.content_text.pack(fill="both", expand=True)
        self.content_text.insert("1.0", content)

        # Validation status
        self.status_label = ctk.CTkLabel(
            self.window, text="",
            font=Fonts.label
        )
        self.status_label.pack(pady=5)

        # Buttons
        btn_frame = ctk.CTkFrame(self.window, fg_color="transparent")
        btn_frame.pack(pady=20)

        btn_validate = ctk.CTkButton(
            btn_frame, text="Validate",
            command=self._validate,
            fg_color=Colors.NAVY,
            font=Fonts.label_large
        )
        btn_validate.pack(side="left", padx=5)

        btn_save = ctk.CTkButton(
            btn_frame, text="Save Changes",
            command=self._save,
            fg_color=Colors.RED,
            hover_color=Colors.RED_DARK,
            font=Fonts.label_large
        )
        btn_save.pack(side="left", padx=5)

        btn_cancel = ctk.CTkButton(
            btn_frame, text="Cancel",
            command=self.close,
            fg_color="gray",
            font=Fonts.label_large
        )
        btn_cancel.pack(side="left", padx=5)

    def _validate(self):
        """Validate the rule content"""
        content = self.content_text.get("1.0", "end-1c").strip()
        is_valid, error_msg = self.app.yara_rule_manager.validate_yara_rule(content)

        if is_valid:
            self.status_label.configure(text="✓ Rule syntax is valid", text_color="green")
        else:
            self.status_label.configure(text=f"✗ {error_msg}", text_color="red")

    def _save(self):
        """Save the edited rule"""
        new_content = self.content_text.get("1.0", "end-1c").strip()

        is_valid, error_msg = self.app.yara_rule_manager.validate_yara_rule(new_content)
        if not is_valid:
            self.status_label.configure(
                text=f"Validation failed: {error_msg}",
                text_color="red"
            )
            return

        create_backup = self.app.settings_manager.get("yara.create_backups_on_update", True)
        success, message = self.app.yara_rule_manager.update_rule(
            self.rule["name"], new_content, create_backup=create_backup
        )

        if success:
            messagebox.showinfo("Success", message)
            self.close()
            self.app.refresh_yara_rules_list()
            self.app.case_manager.load_yara_rules()
        else:
            self.status_label.configure(text=f"Error: {message}", text_color="red")

    def close(self):
        """Close the dialog"""
        if self.window:
            self.window.destroy()


class YaraAddDialog:
    """Dialog for adding a new YARA rule"""

    EXAMPLE_RULE = """rule Example_Rule
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

    def __init__(self, app: 'ForensicAnalysisGUI'):
        self.app = app
        self.window: Optional[ctk.CTkToplevel] = None
        self.name_entry: Optional[ctk.CTkEntry] = None
        self.content_text: Optional[ctk.CTkTextbox] = None
        self.status_label: Optional[ctk.CTkLabel] = None
        self._create_window()

    def _create_window(self):
        """Create the add dialog"""
        self.window = ctk.CTkToplevel(self.app.root)
        self.window.title("Add YARA Rule")
        self.window.geometry("800x600")
        self.window.transient(self.app.root)
        self.window.grab_set()

        # Header
        header = ctk.CTkLabel(
            self.window, text="Create New YARA Rule",
            font=Fonts.header_subsection
        )
        header.pack(pady=20)

        # Rule name input
        name_frame = ctk.CTkFrame(self.window, fg_color="transparent")
        name_frame.pack(fill="x", padx=20, pady=10)

        name_label = ctk.CTkLabel(
            name_frame, text="Rule Filename:",
            font=Fonts.label_large
        )
        name_label.pack(side="left", padx=10)

        self.name_entry = ctk.CTkEntry(
            name_frame, placeholder_text="example.yara",
            font=Fonts.label_large, width=300
        )
        self.name_entry.pack(side="left", padx=10)

        # Rule content text area
        content_label = ctk.CTkLabel(
            self.window, text="Rule Content:",
            font=Fonts.label_large
        )
        content_label.pack(anchor="w", padx=30, pady=(10, 5))

        content_frame = ctk.CTkFrame(self.window)
        content_frame.pack(fill="both", expand=True, padx=20, pady=10)

        self.content_text = ctk.CTkTextbox(content_frame, font=("Courier", 12))
        self.content_text.pack(fill="both", expand=True)
        self.content_text.insert("1.0", self.EXAMPLE_RULE)

        # Validation status
        self.status_label = ctk.CTkLabel(
            self.window, text="",
            font=Fonts.label,
            text_color="yellow"
        )
        self.status_label.pack(pady=5)

        # Buttons
        btn_frame = ctk.CTkFrame(self.window, fg_color="transparent")
        btn_frame.pack(pady=20)

        btn_validate = ctk.CTkButton(
            btn_frame, text="Validate",
            command=self._validate,
            fg_color=Colors.NAVY,
            hover_color=Colors.DARK_BLUE,
            font=Fonts.label_large
        )
        btn_validate.pack(side="left", padx=5)

        btn_add = ctk.CTkButton(
            btn_frame, text="Add Rule",
            command=self._add,
            fg_color=Colors.RED,
            hover_color=Colors.RED_DARK,
            font=Fonts.label_large
        )
        btn_add.pack(side="left", padx=5)

        btn_cancel = ctk.CTkButton(
            btn_frame, text="Cancel",
            command=self.close,
            fg_color="gray",
            font=Fonts.label_large
        )
        btn_cancel.pack(side="left", padx=5)

    def _validate(self):
        """Validate the rule content"""
        content = self.content_text.get("1.0", "end-1c").strip()
        is_valid, error_msg = self.app.yara_rule_manager.validate_yara_rule(content)

        if is_valid:
            self.status_label.configure(text="✓ Rule syntax is valid", text_color="green")
        else:
            self.status_label.configure(text=f"✗ {error_msg}", text_color="red")

    def _add(self):
        """Add the new rule"""
        rule_name = self.name_entry.get().strip()
        rule_content = self.content_text.get("1.0", "end-1c").strip()

        if not rule_name:
            self.status_label.configure(
                text="Please enter a rule filename",
                text_color="red"
            )
            return

        if not rule_content:
            self.status_label.configure(
                text="Please enter rule content",
                text_color="red"
            )
            return

        is_valid, error_msg = self.app.yara_rule_manager.validate_yara_rule(rule_content)
        if not is_valid:
            self.status_label.configure(
                text=f"Validation failed: {error_msg}",
                text_color="red"
            )
            return

        success, message = self.app.yara_rule_manager.add_rule_from_content(
            rule_name, rule_content
        )

        if success:
            messagebox.showinfo("Success", message)
            self.close()
            self.app.refresh_yara_rules_list()
            self.app.case_manager.load_yara_rules()
        else:
            self.status_label.configure(text=f"Error: {message}", text_color="red")

    def close(self):
        """Close the dialog"""
        if self.window:
            self.window.destroy()
