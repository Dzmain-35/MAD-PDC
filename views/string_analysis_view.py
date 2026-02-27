"""
String Analysis View for MAD - Virtualized string table and analysis panel.

Provides:
- VirtualizedStringTable: A ttk.Treeview wrapper that handles 100k+ strings
  by only rendering visible rows plus a configurable buffer.
- StringAnalysisPanel: A panel (inline or popup) with category badges,
  search/regex, export, and the virtualized table.

Designed for Phase 1 of the MAD optimization plan (Memory String Analysis).
"""

import re
import csv
import threading
import tkinter as tk
from tkinter import ttk, filedialog
from typing import List, Dict, Optional, Callable, Tuple, Any
from collections import defaultdict

import customtkinter as ctk
from typography import Fonts

# ---------------------------------------------------------------------------
# String category patterns used for classification
# ---------------------------------------------------------------------------

STRING_CATEGORIES = {
    "url": re.compile(r'https?://[^\s<>"\']+'),
    "ip": re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
    "ip_port": re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b'),
    "domain": re.compile(r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b'),
    "path": re.compile(r'[A-Z]:\\[^\s<>"]+|/[a-z][^\s<>"]+'),
    "registry": re.compile(r'HK[A-Z_]+\\[^\s<>"]+'),
    "api": re.compile(
        r'\b(CreateProcess|WriteFile|RegSetValue|VirtualAlloc|LoadLibrary|'
        r'GetProcAddress|InternetOpen|HttpSendRequest|WinExec|ShellExecute|'
        r'WSAStartup|connect|send|recv)\w*\b'
    ),
    "crypto": re.compile(
        r'\b(AES|RSA|RC4|MD5|SHA|HMAC|Base64|CryptEncrypt|CryptDecrypt|BCrypt)\w*\b'
    ),
    "encoding": re.compile(r'[A-Za-z0-9+/]{20,}={0,2}'),
    "email": re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    ),
}

# Friendly display labels and colours for each category
_CATEGORY_META = {
    "all":      {"label": "All",      "fg": "#e2e8f0", "bg": "#334155"},
    "url":      {"label": "URLs",     "fg": "#93c5fd", "bg": "#1e3a5f"},
    "ip":       {"label": "IPs",      "fg": "#fca5a5", "bg": "#5c1c1c"},
    "ip_port":  {"label": "IP:Port",  "fg": "#fca5a5", "bg": "#5c1c1c"},
    "domain":   {"label": "Domains",  "fg": "#a5f3fc", "bg": "#164e63"},
    "path":     {"label": "Paths",    "fg": "#86efac", "bg": "#14532d"},
    "registry": {"label": "Registry", "fg": "#c4b5fd", "bg": "#4c1d95"},
    "api":      {"label": "APIs",     "fg": "#fbbf24", "bg": "#78350f"},
    "crypto":   {"label": "Crypto",   "fg": "#f9a8d4", "bg": "#831843"},
    "encoding": {"label": "Base64",   "fg": "#d4d4d8", "bg": "#3f3f46"},
    "email":    {"label": "Email",    "fg": "#67e8f9", "bg": "#155e75"},
}

# Badge display order (subset of categories shown in the badge bar)
_BADGE_ORDER = ["all", "url", "ip", "path", "registry", "api"]


def _categorize_string(s: str) -> List[str]:
    """Return a list of category tags that apply to *s*."""
    tags = []
    for cat_name, pattern in STRING_CATEGORIES.items():
        if pattern.search(s):
            tags.append(cat_name)
    return tags


# ═══════════════════════════════════════════════════════════════════════════
# VirtualizedStringTable
# ═══════════════════════════════════════════════════════════════════════════

class VirtualizedStringTable:
    """A wrapper around ``ttk.Treeview`` that efficiently handles 100k+ rows.

    Only the visible rows plus a ±50-row buffer are inserted into the tree
    widget at any time.  A real scrollbar is mapped to the *full* dataset
    length so that the user sees a correctly-sized thumb.

    Each row stores:  (row_number, offset_hex, string, length, type, region)
    """

    # Number of extra rows above/below the viewport to keep in the tree
    BUFFER = 50

    def __init__(self, parent: tk.Widget, colors: dict, is_large_screen: bool = True):
        self.parent = parent
        self.colors = colors
        self.is_large_screen = is_large_screen

        # Data stores
        self.all_data: List[tuple] = []        # full dataset
        self.filtered_data: List[tuple] = []   # after search / category filter
        self._sort_col: Optional[str] = None
        self._sort_reverse: bool = False

        # Viewport tracking
        self._viewport_start = 0   # first visible row index in filtered_data
        self._viewport_end = 0     # last visible row index (exclusive)
        self._inserted_start = 0
        self._inserted_end = 0

        # Build widgets
        self._frame = tk.Frame(parent, bg="#1a1a1a")
        self._frame.pack(fill="both", expand=True)

        self._build_tree()

    # ── widget property ──────────────────────────────────────────────────
    @property
    def frame(self):
        return self._frame

    # ── build ─────────────────────────────────────────────────────────────
    def _build_tree(self):
        _font_size = 12 if self.is_large_screen else 10
        _heading_size = 13 if self.is_large_screen else 11
        _row_height = 26 if self.is_large_screen else 22

        style = ttk.Style()
        style.configure(
            "StringTable.Treeview",
            background="#1a1a1a", foreground="white",
            fieldbackground="#1a1a1a", borderwidth=0,
            relief="flat", font=("Courier", _font_size),
            rowheight=_row_height,
        )
        style.configure(
            "StringTable.Treeview.Heading",
            background="#0d1520", foreground="white",
            borderwidth=1, relief="flat",
            font=("Segoe UI", _heading_size, "bold"),
        )
        style.map(
            "StringTable.Treeview",
            background=[("selected", "#dc2626")],
            foreground=[("selected", "white")],
        )
        style.map(
            "StringTable.Treeview.Heading",
            background=[("active", "#1a2332")],
        )

        columns = ("#", "Offset", "String", "Length", "Type", "Region")
        self.tree = ttk.Treeview(
            self._frame, columns=columns, show="headings",
            style="StringTable.Treeview",
        )

        # Vertical scrollbar mapped to full dataset
        self._vsb = tk.Scrollbar(
            self._frame, orient="vertical",
            bg="#1a1a1a", troughcolor="#0d1520",
        )
        self._vsb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

        # Column widths
        col_cfg = {
            "#":       (60,  40,  "center"),
            "Offset":  (120, 80,  "center"),
            "String":  (500, 200, "w"),
            "Length":  (70,  50,  "center"),
            "Type":    (80,  60,  "center"),
            "Region":  (120, 80,  "center"),
        }
        for col, (width, minw, anchor) in col_cfg.items():
            self.tree.column(col, width=width, minwidth=minw, anchor=anchor)
            self.tree.heading(
                col, text=col,
                command=lambda c=col: self.sort_by_column(c),
            )

        # Override the scrollbar to control virtual scrolling
        self._vsb.config(command=self._on_scrollbar)
        self.tree.configure(yscrollcommand=self._on_tree_scroll)

        # Bind mousewheel for virtual scroll
        self.tree.bind("<MouseWheel>", self._on_mousewheel)
        self.tree.bind("<Button-4>", self._on_mousewheel_linux)
        self.tree.bind("<Button-5>", self._on_mousewheel_linux)

        # Tag styles
        self.tree.tag_configure("url",      foreground="#93c5fd")
        self.tree.tag_configure("ip",       foreground="#fca5a5")
        self.tree.tag_configure("ip_port",  foreground="#fca5a5")
        self.tree.tag_configure("path",     foreground="#86efac")
        self.tree.tag_configure("registry", foreground="#c4b5fd")
        self.tree.tag_configure("api",      foreground="#fbbf24")
        self.tree.tag_configure("crypto",   foreground="#f9a8d4")
        self.tree.tag_configure("encoding", foreground="#d4d4d8")
        self.tree.tag_configure("email",    foreground="#67e8f9")
        self.tree.tag_configure("domain",   foreground="#a5f3fc")

        # Store row height for calculations
        self._row_height = int(style.lookup("StringTable.Treeview", "rowheight") or 26)

    # ── public API ────────────────────────────────────────────────────────

    def set_data(self, strings_with_metadata: List[tuple]):
        """Load data into the table.

        Each element is a tuple:
            (row_number, offset_hex, string, length, type_str, region_str)
        """
        self.all_data = list(strings_with_metadata)
        self.filtered_data = list(self.all_data)
        self._sort_col = None
        self._sort_reverse = False
        self._full_rebuild()

    def search(self, term: str, regex: bool = False):
        """Filter visible rows to those matching *term*."""
        if not term:
            self.filtered_data = list(self.all_data)
        else:
            if regex:
                try:
                    pat = re.compile(term, re.IGNORECASE)
                except re.error:
                    return  # invalid regex, do nothing
                self.filtered_data = [
                    row for row in self.all_data if pat.search(row[2])
                ]
            else:
                lower_term = term.lower()
                self.filtered_data = [
                    row for row in self.all_data if lower_term in row[2].lower()
                ]
        self._full_rebuild()

    def filter_by_category(self, category: str):
        """Show only strings matching *category* (or 'all')."""
        if category == "all" or not category:
            self.filtered_data = list(self.all_data)
        else:
            pattern = STRING_CATEGORIES.get(category)
            if pattern:
                self.filtered_data = [
                    row for row in self.all_data if pattern.search(row[2])
                ]
            else:
                self.filtered_data = list(self.all_data)
        self._full_rebuild()

    def sort_by_column(self, col: str):
        """Sort the filtered data by column. Toggle direction on re-click."""
        col_index_map = {
            "#": 0, "Offset": 1, "String": 2,
            "Length": 3, "Type": 4, "Region": 5,
        }
        idx = col_index_map.get(col, 2)
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = False
        try:
            self.filtered_data.sort(key=lambda r: r[idx], reverse=self._sort_reverse)
        except TypeError:
            self.filtered_data.sort(key=lambda r: str(r[idx]), reverse=self._sort_reverse)
        self._full_rebuild()

    def get_selected_rows(self) -> List[tuple]:
        """Return data tuples for all currently selected tree items."""
        rows = []
        for iid in self.tree.selection():
            vals = self.tree.item(iid, "values")
            if vals:
                rows.append(vals)
        return rows

    def clear(self):
        """Remove all data and clear the tree."""
        self.all_data.clear()
        self.filtered_data.clear()
        self.tree.delete(*self.tree.get_children())
        self._update_scrollbar()

    # ── internal: full rebuild ────────────────────────────────────────────

    def _full_rebuild(self):
        """Delete all tree items and repopulate from *filtered_data*."""
        self.tree.delete(*self.tree.get_children())
        self._inserted_start = 0
        self._inserted_end = 0
        self._viewport_start = 0
        self._rebuild_viewport()
        self._update_scrollbar()

    # ── internal: virtualized viewport ────────────────────────────────────

    def _visible_row_count(self) -> int:
        """Estimate how many rows fit in the visible area."""
        self.tree.update_idletasks()
        height = self.tree.winfo_height()
        if height <= 1:
            height = 400  # fallback before first paint
        return max(1, height // max(self._row_height, 1))

    def _rebuild_viewport(self):
        """Ensure the tree contains the visible rows ± BUFFER."""
        total = len(self.filtered_data)
        if total == 0:
            self.tree.delete(*self.tree.get_children())
            self._inserted_start = 0
            self._inserted_end = 0
            return

        visible = self._visible_row_count()
        start = max(0, self._viewport_start - self.BUFFER)
        end = min(total, self._viewport_start + visible + self.BUFFER)

        # Avoid rebuild if the range hasn't changed
        if start == self._inserted_start and end == self._inserted_end:
            return

        self.tree.delete(*self.tree.get_children())

        for i in range(start, end):
            row = self.filtered_data[i]
            # row = (row_number, offset_hex, string, length, type_str, region_str)
            string_val = row[2]
            tags = _categorize_string(string_val)
            tag_tuple = tuple(tags[:1]) if tags else ()  # use first matching category
            self.tree.insert(
                "", "end",
                iid=str(i),
                values=row,
                tags=tag_tuple,
            )

        self._inserted_start = start
        self._inserted_end = end

    # ── scrollbar handling ────────────────────────────────────────────────

    def _update_scrollbar(self):
        """Reposition the scrollbar thumb to reflect current viewport."""
        total = len(self.filtered_data)
        if total == 0:
            self._vsb.set(0, 1)
            return
        visible = self._visible_row_count()
        first = self._viewport_start / total
        last = min(1.0, (self._viewport_start + visible) / total)
        self._vsb.set(first, last)

    def _on_scrollbar(self, *args):
        """Handle scrollbar interaction to control virtual viewport."""
        total = len(self.filtered_data)
        if total == 0:
            return
        action = args[0]
        if action == "moveto":
            fraction = float(args[1])
            self._viewport_start = max(0, int(fraction * total))
        elif action == "scroll":
            delta = int(args[1])
            unit = args[2]
            if unit == "units":
                self._viewport_start = max(0, min(
                    total - 1, self._viewport_start + delta))
            else:  # pages
                visible = self._visible_row_count()
                self._viewport_start = max(0, min(
                    total - 1, self._viewport_start + delta * visible))
        self._rebuild_viewport()
        self._update_scrollbar()

    def _on_tree_scroll(self, first, last):
        """Called by treeview's yscrollcommand — redirect to virtual bar."""
        # We override the native scroll; just update the virtual bar
        self._update_scrollbar()

    def _on_mousewheel(self, event):
        """Handle mousewheel on Windows/macOS."""
        total = len(self.filtered_data)
        if total == 0:
            return "break"
        delta = -1 * (event.delta // 120) if event.delta else 0
        self._viewport_start = max(0, min(
            total - 1, self._viewport_start + delta * 3))
        self._rebuild_viewport()
        self._update_scrollbar()
        return "break"

    def _on_mousewheel_linux(self, event):
        """Handle mousewheel on Linux (Button-4 / Button-5)."""
        total = len(self.filtered_data)
        if total == 0:
            return "break"
        delta = -3 if event.num == 4 else 3
        self._viewport_start = max(0, min(
            total - 1, self._viewport_start + delta))
        self._rebuild_viewport()
        self._update_scrollbar()
        return "break"


# ═══════════════════════════════════════════════════════════════════════════
# StringAnalysisPanel
# ═══════════════════════════════════════════════════════════════════════════

class StringAnalysisPanel:
    """High-level panel combining category badges, search bar,
    VirtualizedStringTable, export, and status bar.

    Can be embedded in a parent frame (inline) or used inside a
    ``ctk.CTkToplevel`` popup window.
    """

    def __init__(
        self,
        parent: tk.Widget,
        app,
        colors: dict,
        is_large_screen: bool = True,
        lightweight: bool = False,
        max_per_category: int = 0,
    ):
        """
        Args:
            parent: Parent widget.
            app: Reference to the main ForensicAnalysisGUI.
            colors: Colour scheme dict.
            is_large_screen: Display-density flag.
            lightweight: If True, show a compact version (used in the
                         inline quick-view panel).
            max_per_category: When > 0, limit category badge counts
                              to this many strings per category.
        """
        self.parent = parent
        self.app = app
        self.colors = colors
        self.is_large_screen = is_large_screen
        self.lightweight = lightweight
        self.max_per_category = max_per_category

        self._pid: Optional[int] = None
        self._scan_mode: str = "quick"
        self._extraction_result: Optional[dict] = None
        self._active_category: str = "all"

        # Category counts
        self._cat_counts: Dict[str, int] = {}
        self._cat_badge_buttons: Dict[str, ctk.CTkButton] = {}

        # Root frame for the whole panel
        self.frame = ctk.CTkFrame(parent, fg_color=colors["dark_blue"])

        self._build()

    # ── build ─────────────────────────────────────────────────────────────

    def _build(self):
        # --- Category badge bar ---
        badge_bar = ctk.CTkFrame(self.frame, fg_color="transparent", height=36)
        badge_bar.pack(fill="x", padx=8, pady=(6, 2))

        for cat in _BADGE_ORDER:
            meta = _CATEGORY_META.get(cat, _CATEGORY_META["all"])
            btn = ctk.CTkButton(
                badge_bar,
                text=f"{meta['label']}(0)",
                font=("Segoe UI", 11, "bold"),
                text_color=meta["fg"],
                fg_color=meta["bg"],
                hover_color=meta["bg"],
                corner_radius=6,
                height=26,
                width=80,
                command=lambda c=cat: self._on_badge_click(c),
            )
            btn.pack(side="left", padx=2)
            self._cat_badge_buttons[cat] = btn

        # --- Search bar ---
        search_row = ctk.CTkFrame(self.frame, fg_color="transparent", height=36)
        search_row.pack(fill="x", padx=8, pady=(2, 4))

        self._search_entry = ctk.CTkEntry(
            search_row,
            placeholder_text="Search strings...",
            height=30,
            width=260 if self.is_large_screen else 180,
            fg_color="gray20",
            border_color=self.colors["navy"],
            border_width=2,
        )
        self._search_entry.pack(side="left", padx=(0, 4))
        self._search_entry.bind("<Return>", lambda _e: self._do_search())

        self._regex_var = tk.BooleanVar(value=False)
        regex_chk = ctk.CTkCheckBox(
            search_row, text="Regex",
            variable=self._regex_var,
            height=26, width=60,
            checkbox_height=18, checkbox_width=18,
            fg_color=self.colors["red"],
            hover_color=self.colors["red_dark"],
        )
        regex_chk.pack(side="left", padx=4)

        search_btn = ctk.CTkButton(
            search_row, text="Search",
            command=self._do_search,
            height=28, width=70,
            fg_color=self.colors["navy"],
            hover_color=self.colors["dark_blue"],
        )
        search_btn.pack(side="left", padx=4)

        clear_btn = ctk.CTkButton(
            search_row, text="Clear",
            command=self._clear_search,
            height=28, width=60,
            fg_color="gray30",
            hover_color="gray40",
        )
        clear_btn.pack(side="left", padx=4)

        if not self.lightweight:
            # Export button
            self._export_btn = ctk.CTkButton(
                search_row, text="Export",
                command=self._export,
                height=28, width=70,
                fg_color="#065f46",
                hover_color="#047857",
            )
            self._export_btn.pack(side="right", padx=4)

        # --- Virtualized table ---
        table_frame = ctk.CTkFrame(self.frame, fg_color="#1a1a1a")
        table_frame.pack(fill="both", expand=True, padx=8, pady=(0, 2))

        self.table = VirtualizedStringTable(
            table_frame, self.colors, self.is_large_screen,
        )

        # --- Status bar ---
        self._status_label = ctk.CTkLabel(
            self.frame, text="No data loaded",
            font=Fonts.status, text_color="#9ca3af",
            anchor="w",
        )
        self._status_label.pack(fill="x", padx=10, pady=(0, 4))

    # ── public API ────────────────────────────────────────────────────────

    def load_strings(self, pid: int, scan_mode: str = "quick"):
        """Trigger extraction in a background thread, update progressively."""
        self._pid = pid
        self._scan_mode = scan_mode
        self._status_label.configure(
            text=f"Scanning PID {pid} ({scan_mode} mode)...")

        def _worker():
            try:
                extractor = getattr(self.app.process_monitor, 'memory_extractor', None)
                if not extractor:
                    self.frame.after(
                        0,
                        lambda: self._status_label.configure(
                            text="Memory extractor not available"),
                    )
                    return
                result = extractor.extract_strings_from_memory(
                    pid=pid,
                    min_length=4,
                    max_strings=500000,
                    include_unicode=True,
                    enable_quality_filter=True,
                    scan_mode=scan_mode,
                    return_offsets=True,
                    progress_callback=self._progress_cb,
                )
                # Schedule final update on main thread
                self.frame.after(0, lambda: self.set_strings_data(result))
            except Exception as exc:
                self.frame.after(
                    0,
                    lambda: self._status_label.configure(
                        text=f"Error: {exc}"),
                )

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    def set_strings_data(self, extraction_result: dict):
        """Populate the table from a MemoryStringExtractor result dict."""
        self._extraction_result = extraction_result

        # Build flat row list from strings_by_region
        rows: List[tuple] = []
        row_num = 1
        for region_data in extraction_result.get("strings_by_region", []):
            region = region_data.get("region", {})
            region_label = f"{region.get('type', '?').upper()} {region.get('protection', '')}"
            for entry in region_data.get("strings", []):
                if isinstance(entry, tuple) and len(entry) == 3:
                    # (offset_hex, string, encoding)
                    offset_hex, string, encoding = entry
                else:
                    # Plain string (non-offset mode)
                    string = str(entry)
                    offset_hex = ""
                    encoding = "ascii"
                rows.append((
                    row_num,
                    offset_hex,
                    string,
                    len(string),
                    encoding,
                    region_label,
                ))
                row_num += 1

        # Apply max_per_category limit if in lightweight mode
        if self.max_per_category > 0 and len(rows) > self.max_per_category:
            rows = rows[:self.max_per_category]

        self.table.set_data(rows)
        self._update_category_counts(rows)

        scan_mode = extraction_result.get("scan_mode", self._scan_mode)
        pid = extraction_result.get("pid", self._pid)
        total = len(rows)
        self._status_label.configure(
            text=f"PID {pid} | {total:,} strings | {scan_mode} scan"
        )

    # ── internal helpers ──────────────────────────────────────────────────

    def _progress_cb(self, current_strings, regions_total, regions_read, final=False):
        """Called from the extractor background thread."""
        count = sum(
            len(v) if isinstance(v, list) else 0
            for v in current_strings.values()
        )
        msg = f"Scanning: {count:,} strings | {regions_read}/{regions_total} regions"
        if final:
            msg = f"Complete: {count:,} strings"
        try:
            self.frame.after(0, lambda: self._status_label.configure(text=msg))
        except Exception:
            pass

    def _update_category_counts(self, rows: List[tuple]):
        """Recompute category counts and update badge labels."""
        counts: Dict[str, int] = {"all": len(rows)}
        for cat in STRING_CATEGORIES:
            counts[cat] = 0

        for row in rows:
            string_val = row[2]
            for cat_name, pattern in STRING_CATEGORIES.items():
                if pattern.search(string_val):
                    counts[cat_name] = counts.get(cat_name, 0) + 1

        self._cat_counts = counts
        for cat, btn in self._cat_badge_buttons.items():
            meta = _CATEGORY_META.get(cat, _CATEGORY_META["all"])
            cnt = counts.get(cat, 0)
            btn.configure(text=f"{meta['label']}({cnt:,})")

    def _on_badge_click(self, category: str):
        """Handle click on a category badge."""
        self._active_category = category
        # Highlight the active badge
        for cat, btn in self._cat_badge_buttons.items():
            meta = _CATEGORY_META.get(cat, _CATEGORY_META["all"])
            if cat == category:
                btn.configure(
                    fg_color=self.colors["red"],
                    hover_color=self.colors["red_dark"],
                )
            else:
                btn.configure(
                    fg_color=meta["bg"],
                    hover_color=meta["bg"],
                )
        self.table.filter_by_category(category)
        count = len(self.table.filtered_data)
        self._status_label.configure(
            text=f"PID {self._pid} | Showing {count:,} strings "
                 f"({_CATEGORY_META.get(category, {}).get('label', category)})"
        )

    def _do_search(self):
        term = self._search_entry.get().strip()
        use_regex = self._regex_var.get()
        self.table.search(term, regex=use_regex)
        count = len(self.table.filtered_data)
        if term:
            self._status_label.configure(
                text=f"Search: {count:,} matches for '{term}'"
            )
        else:
            total = len(self.table.all_data)
            self._status_label.configure(
                text=f"PID {self._pid} | {total:,} strings"
            )

    def _clear_search(self):
        self._search_entry.delete(0, "end")
        self.table.search("")
        self._active_category = "all"
        for cat, btn in self._cat_badge_buttons.items():
            meta = _CATEGORY_META.get(cat, _CATEGORY_META["all"])
            btn.configure(fg_color=meta["bg"], hover_color=meta["bg"])
        total = len(self.table.all_data)
        self._status_label.configure(
            text=f"PID {self._pid} | {total:,} strings"
        )

    def _export(self):
        """Export to TXT or CSV via file dialog."""
        if not self._extraction_result:
            return
        filetypes = [("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")]
        path = filedialog.asksaveasfilename(
            title="Export Strings",
            defaultextension=".csv",
            filetypes=filetypes,
        )
        if not path:
            return
        try:
            if path.lower().endswith(".csv"):
                self._export_csv(path)
            else:
                self._export_txt(path)
            self._status_label.configure(text=f"Exported to {path}")
        except Exception as exc:
            self._status_label.configure(text=f"Export error: {exc}")

    def _export_csv(self, path: str):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["#", "Offset", "String", "Length", "Type", "Region"])
            for row in self.table.filtered_data:
                writer.writerow(row)

    def _export_txt(self, path: str):
        if self._extraction_result and self.app:
            try:
                extractor = self.app.process_monitor.memory_extractor
                extractor.export_to_txt(self._extraction_result, path)
                return
            except Exception:
                pass
        # Fallback: plain text dump
        with open(path, "w", encoding="utf-8") as f:
            for row in self.table.filtered_data:
                f.write(f"{row[1]}  {row[2]}\n")
