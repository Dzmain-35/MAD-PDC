# MAD Full Optimization Plan

**Target Audience**: Experienced malware analysts who need a fast, lightweight, powerful analysis platform
**Framework**: Python / CustomTkinter / ttk.Treeview
**Guiding Principle**: Speed above all. Every interaction should feel instant. Think Process Hacker responsiveness.

---

## Architecture Overview: Current State

```
MAD.py (8660 lines, monolithic)
├── ForensicAnalysisGUI class
│   ├── Sidebar: New Case | Current Case | Analysis | YARA Rules | Settings
│   ├── Analysis Tab
│   │   ├── Processes sub-tab (process tree + collapsible HTTP panel)
│   │   └── Live Events sub-tab (system-wide monitoring)
│   └── Process Details → popup window (CTkToplevel)
│       ├── Process Info tab
│       ├── Strings tab (1000-string display limit, plain tk.Text)
│       └── Live Events tab (per-process)
│
analysis_modules/
├── memory_string_extractor.py   (Windows API: ReadProcessMemory)
├── file_string_extractor.py     (mmap-based file strings)
├── process_monitor.py           (real-time monitoring + YARA)
├── network_monitor.py           (psutil TCP/UDP polling)
├── http_monitor.py              (HTTP/HTTPS session tracking)
├── process_activity_monitor.py  (per-PID procmon-style events)
├── system_wide_monitor.py       (combined system monitoring)
├── procmon_events.py            (event structures)
├── sysmon_parser.py             (Windows Sysmon log parsing)
├── persistence_monitor.py       (registry/scheduled task detection)
├── sigma_evaluator.py           (in-memory Sigma rule evaluation)
└── process_memory_tree_filtered.py (procmon-style file filtering)
```

---

## Phase 0: Modularization (Foundation)

**Priority**: P0 — Must happen first to enable all other phases
**Goal**: Break the 8660-line monolith into maintainable view modules

### 0.1 Extract View Modules from MAD.py

Split `ForensicAnalysisGUI` into composable view classes. Each view owns its own frame, widgets, and event handlers. The main `MAD.py` becomes a thin shell that initializes the app, manages the sidebar, and coordinates between views.

**New file structure:**
```
MAD.py                          (~800 lines - app shell, sidebar, routing)
views/
├── __init__.py
├── base_view.py                (BaseView class with shared utilities)
├── new_case_view.py            (New Case form + branding)
├── current_case_view.py        (Case display + IOC management)
├── process_view.py             (Process tree + HTTP panel + string quick-view)
├── live_events_view.py         (System-wide event monitoring)
├── network_view.py             (NEW: dedicated network analysis)
├── string_analysis_view.py     (NEW: enhanced string analysis window)
├── yara_rules_view.py          (YARA rule management)
├── settings_view.py            (Settings management)
└── shared_widgets.py           (Reusable widget components)
```

**BaseView contract:**
```python
class BaseView:
    def __init__(self, parent, app, colors):
        self.frame = ctk.CTkFrame(parent, fg_color=colors["dark_blue"])
        self.app = app          # Reference to main app for cross-view communication
        self.colors = colors

    def show(self):
        """Called when this view becomes visible"""
        self.frame.pack(fill="both", expand=True)

    def hide(self):
        """Called when switching away from this view"""
        self.frame.pack_forget()

    def on_activate(self):
        """Hook for when view gains focus (refresh data, etc.)"""
        pass

    def destroy(self):
        """Clean up resources"""
        pass
```

**MAD.py slim shell responsibilities:**
- Window creation, theming, screen detection
- Sidebar navigation with button state management
- View registry and tab switching
- Cross-view event bus (e.g., "process selected" → update string panel)
- Keyboard shortcut registration
- Application lifecycle (start monitoring, stop, cleanup)

**Implementation steps:**
1. Create `views/base_view.py` with `BaseView` class
2. Create `views/shared_widgets.py` with reusable components (search bars, filtered treeviews, status bars)
3. Extract `create_new_case_tab` → `views/new_case_view.py`
4. Extract `create_current_case_tab` → `views/current_case_view.py`
5. Extract `create_processes_subtab` + all process tree logic → `views/process_view.py`
6. Extract `create_live_events_subtab` + event refresh logic → `views/live_events_view.py`
7. Extract `create_yara_rules_tab` → `views/yara_rules_view.py`
8. Extract `create_settings_tab` → `views/settings_view.py`
9. Wire cross-view events through the app shell
10. Verify all existing functionality works identically

**Risk mitigation:** Extract one view at a time, test after each extraction. Process view is the most complex — extract it last.

---

## Phase 1: Memory String Analysis (Speed + Volume)

**Priority**: P0 — This is the #1 analyst workflow bottleneck
**Goal**: Process Hacker-level string extraction speed with 100k+ string display capability

### Current Bottlenecks Identified
| Issue | Location | Impact |
|-------|----------|--------|
| 1000-string display limit | `MAD.py:7038, 7052` | Analysts see <5% of extracted strings |
| Category display caps (50/50/50/200) | `MAD.py:7175-7184` | URLs, IPs, paths severely truncated |
| 20,000 extraction limit | `MAD.py:7156` | Deep scans miss strings in large processes |
| Plain `tk.Text` widget | `MAD.py:6991-7002` | No virtualization, freezes at >5000 strings |
| Popup window context loss | `MAD.py:6608` | Breaks analysis flow, can't see tree + strings simultaneously |
| No hex offset display | `memory_string_extractor.py` | Missing critical forensic context |
| No string deduplication view | N/A | Analyst wastes time on repeated strings |

### 1.1 Virtualized String Table (P0)

Replace the `tk.Text` widget with a virtualized `ttk.Treeview` that can handle 100,000+ strings without lag. The key insight: Treeview only renders visible rows, so it can handle massive datasets if we avoid inserting all rows at once.

**File**: `views/string_analysis_view.py` (new)

**String table columns:**
```
| # | Offset (Hex) | String | Length | Type | Region |
```

- **#**: Row number for quick reference
- **Offset**: Memory address in hex (e.g., `0x7FF612A40000`) — critical for forensic context
- **String**: The extracted string value
- **Length**: Character count for quick size assessment
- **Type**: Category tag (ASCII, Unicode, URL, IP, Path, Registry, Environment, API)
- **Region**: Memory region type (IMAGE, PRIVATE, MAPPED) + protection flags

**Virtualization strategy:**
- Extract ALL strings into an in-memory list (no display limit)
- TreeView inserts only visible rows + buffer (±50 rows above/below viewport)
- On scroll, dynamically insert/remove rows
- Maintain a `visible_range` tracker that updates on `<Configure>` and scroll events

**Implementation:**
```python
class VirtualizedStringTable:
    """Handles 100k+ strings with instant scrolling"""

    def __init__(self, parent, columns):
        self.all_data = []          # Full dataset
        self.filtered_data = []     # After search/filter applied
        self.tree = ttk.Treeview(parent, columns=columns, show="headings")
        self.scrollbar = tk.Scrollbar(parent, command=self._on_scroll)
        self.tree.configure(yscrollcommand=self._on_tree_scroll)

        # Track viewport
        self._visible_count = 50    # Rows visible at once
        self._buffer = 25           # Extra rows above/below
        self._current_offset = 0

    def set_data(self, strings_with_metadata):
        """Load entire dataset — does NOT insert into tree"""
        self.all_data = strings_with_metadata
        self.filtered_data = self.all_data
        self._rebuild_viewport()

    def _rebuild_viewport(self):
        """Clear tree and insert only visible rows"""
        self.tree.delete(*self.tree.get_children())
        start = max(0, self._current_offset - self._buffer)
        end = min(len(self.filtered_data), self._current_offset + self._visible_count + self._buffer)
        for i in range(start, end):
            row = self.filtered_data[i]
            self.tree.insert("", "end", values=row, iid=str(i))

    def search(self, term, regex=False):
        """Filter dataset — instant because it operates on in-memory list"""
        if not term:
            self.filtered_data = self.all_data
        elif regex:
            pattern = re.compile(term, re.IGNORECASE)
            self.filtered_data = [r for r in self.all_data if pattern.search(r[2])]
        else:
            term_lower = term.lower()
            self.filtered_data = [r for r in self.all_data if term_lower in r[2].lower()]
        self._current_offset = 0
        self._rebuild_viewport()
```

### 1.2 Dual-Mode String Panel: Inline Quick-View + Pop-Out Deep Analysis (P0)

**Rationale from user feedback**: On laptops/small screens, too many inline panels get cramped. Solution: a lightweight inline panel that shows key data fast, with a pop-out button for full deep analysis.

#### Inline Quick-View Panel (docked below process tree)
- Appears when analyst selects a process in the tree (single-click or Enter)
- Shows in the lower portion of the process view via `tk.PanedWindow`
- Contains: category summary badges + top strings (first 100 of each category)
- Collapsible with a toggle button or keyboard shortcut
- **Speed target**: populated within 200ms of process selection (use cached quick scan)

**Layout when inline panel is open:**
```
┌─────────────────────────────────────────────────┐
│ Process Analysis        [Search] [Filter ▾]     │
│ YARA: 3  SIGMA: 1  HTTP ▾  NET: 12             │
├─────────────────────────────────────────────────┤
│ Process Tree                                     │
│ ├── explorer.exe (PID 4012)                     │
│ │   ├── chrome.exe (PID 8844)                   │
│ │   └── ▶ malware.exe (PID 6120)  ⚠️ YARA     │ ← selected
│ └── services.exe (PID 672)                      │
│                                                  │
├─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤ ← PanedWindow sash (draggable)
│ Quick Strings: malware.exe (PID 6120)  [⤢ Pop] │
│ URLs(12) IPs(4) Paths(23) Registry(8) All(847)  │ ← clickable category tabs
│ ┌───────────────────────────────────────────┐   │
│ │ http://c2.evil.com/beacon                 │   │
│ │ http://updates.malware.net/config.dat     │   │
│ │ https://pastebin.com/raw/xK2mN9           │   │
│ │ ...                                        │   │
│ └───────────────────────────────────────────┘   │
└─────────────────────────────────────────────────┘
```

#### Pop-Out Deep Analysis Window (enhanced popup)
- Launched via "Pop Out" button (⤢) on the inline panel or keyboard shortcut
- Full `VirtualizedStringTable` with all columns (offset, type, region)
- No string count limits — shows every extracted string
- Advanced search with regex support
- Multi-column sorting (by offset, length, type, frequency)
- String frequency analysis (deduplicated view with occurrence count)
- Export to TXT/CSV/JSON with full metadata
- Context menu: Copy string, Copy offset, Add to case IOCs, Search in VirusTotal

**File**: `views/string_analysis_view.py`

### 1.3 Memory String Extractor Performance Optimizations (P0)

**File**: `analysis_modules/memory_string_extractor.py`

**Changes:**

1. **Remove extraction limit** — Currently capped at 20,000 (`MAD.py:7156`). Replace with configurable limit defaulting to 500,000. For processes with millions of strings, implement streaming extraction.

2. **Return hex offsets with strings** — Modify `extract_strings()` to return `(offset, string, encoding, region_type)` tuples instead of plain strings. The offset is `region.BaseAddress + position_in_buffer`.

3. **Parallel region scanning** — Use `concurrent.futures.ThreadPoolExecutor` to read multiple memory regions simultaneously. Windows API calls are I/O-bound (cross-process memory reads), so threading helps.

4. **Smarter region prioritization** — Scan IMAGE regions first (most likely to contain interesting strings), then PRIVATE (heap/stack), then MAPPED. This gives analysts useful results faster during progressive loading.

5. **Incremental cache** — Instead of 30-second full-cache TTL, cache per-region. When an analyst re-scans, only re-read regions whose page protection changed (indicates memory was written to). Check via `VirtualQueryEx` comparison.

6. **String deduplication with frequency** — Track `{string: count}` during extraction. The deep analysis view can show unique strings sorted by frequency — repeated strings are often C2 beacons or decrypted configs.

### 1.4 Category-Aware String Classification (P1)

**File**: `analysis_modules/memory_string_extractor.py`

Enhance the existing categorization to be more precise and analyst-relevant:

```python
STRING_CATEGORIES = {
    "url":        r'https?://[^\s<>"\']+',
    "ip":         r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    "ip_port":    r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\b',
    "domain":     r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b',
    "path":       r'[A-Z]:\\[^\s<>"]+|/[a-z][^\s<>"]+',
    "registry":   r'HK[A-Z_]+\\[^\s<>"]+',
    "api":        r'\b(CreateProcess|WriteFile|RegSetValue|VirtualAlloc|LoadLibrary|GetProcAddress|InternetOpen|HttpSendRequest|WinExec|ShellExecute|WSAStartup|connect|send|recv)\w*\b',
    "crypto":     r'\b(AES|RSA|RC4|MD5|SHA|HMAC|Base64|CryptEncrypt|CryptDecrypt|BCrypt)\w*\b',
    "encoding":   r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64-like
    "email":      r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "useragent":  r'Mozilla/\d|User-Agent:',
    "environment": r'%[A-Z_]+%',
}
```

Each string gets tagged with zero or more categories. The inline panel shows category badges with counts. Clicking a badge filters to that category instantly.

---

## Phase 2: Layout & Flow Optimization

**Priority**: P0-P1
**Goal**: Analysts move fluidly between process tree, strings, events, and network without losing context

### 2.1 Keyboard Shortcuts (P0)

**File**: `MAD.py` (app shell) + each view module

Zero keyboard shortcuts exist today. For power analysts, this is a critical gap.

**Global shortcuts (registered on root window):**
```
Ctrl+1          → Switch to New Case tab
Ctrl+2          → Switch to Current Case tab
Ctrl+3          → Switch to Analysis tab
Ctrl+4          → Switch to YARA Rules tab
Ctrl+5          → Switch to Settings tab

Ctrl+Shift+P    → Focus Processes sub-tab
Ctrl+Shift+E    → Focus Live Events sub-tab
Ctrl+Shift+N    → Focus Network sub-tab

Ctrl+F          → Focus search bar in current view
Ctrl+K          → Command palette (future phase)
F5              → Refresh current view
Escape          → Close popup / collapse inline panel
```

**Process view shortcuts:**
```
Enter           → Open string quick-view for selected process
Ctrl+Enter      → Open full string analysis (pop-out)
Delete          → Kill selected process (with confirmation)
Ctrl+S          → Scan selected process with YARA
Ctrl+D          → View process details
Ctrl+C          → Copy selected row data
```

**String panel shortcuts:**
```
Ctrl+F          → Focus string search
Ctrl+Shift+F    → Toggle regex mode
Ctrl+E          → Export strings
Ctrl+A          → Select all visible strings
Tab             → Cycle through category tabs (URLs→IPs→Paths→etc.)
```

**Implementation:**
```python
# In MAD.py app shell
def _register_global_shortcuts(self):
    self.root.bind("<Control-Key-1>", lambda e: self.show_tab("new_case"))
    self.root.bind("<Control-Key-2>", lambda e: self.show_tab("current_case"))
    self.root.bind("<Control-Key-3>", lambda e: self.show_tab("analysis"))
    self.root.bind("<Control-Key-4>", lambda e: self.show_tab("yara_rules"))
    self.root.bind("<Control-Key-5>", lambda e: self.show_tab("settings"))
    self.root.bind("<F5>", lambda e: self._refresh_current_view())
    self.root.bind("<Escape>", lambda e: self._handle_escape())
    # ... etc
```

### 2.2 Analysis Tab Restructuring (P0)

**Current**: 2 sub-tabs (Processes, Live Events)
**Target**: 3 sub-tabs (Processes, Live Events, Network)

**Sub-tab bar layout:**
```
[ ⚙️ Processes ] [ 📡 Live Events ] [ 🌐 Network ]
```

The HTTP panel currently embedded under the process tree (`_http_panel`, `_process_paned`) stays there but is optimized to show only HTTP/HTTPS traffic per the user's direction. The new Network sub-tab handles the broader TCP/UDP/DNS analysis.

### 2.3 Process View Split-Pane with Responsive Layout (P1)

**File**: `views/process_view.py`

Replace the current fixed layout with a `tk.PanedWindow` that adapts to screen size:

**Large screen (>1600px width):**
```
┌──────────────────────┬──────────────────────┐
│ Process Tree         │ String Quick-View    │
│                      │ (right panel)        │
│                      │                      │
├──────────────────────┴──────────────────────┤
│ HTTP Traffic (collapsible)                   │
└──────────────────────────────────────────────┘
```

**Small screen / laptop (<1600px width):**
```
┌─────────────────────────────────────────────┐
│ Process Tree                                 │
│                                              │
├─────────────────────────────────────────────┤
│ String Quick-View (bottom panel)             │
├─────────────────────────────────────────────┤
│ HTTP Traffic (collapsible)                   │
└─────────────────────────────────────────────┘
```

Detection via `self.root.winfo_screenwidth()` (already used in the codebase for `_is_large_screen`). The PanedWindow orientation flips between `HORIZONTAL` (large) and `VERTICAL` (small).

### 2.4 Breadcrumb / Context Bar (P2)

Add a thin context bar below the sub-tab buttons that shows the current analysis drill-down path:

```
Analysis > Processes > malware.exe (PID 6120) > Strings > URLs
```

Each segment is clickable to navigate back to that level. This replaces the need to mentally track where you are when switching between inline panels.

### 2.5 Cross-View Event Bus (P1)

**File**: `MAD.py` app shell

Views need to communicate without direct references to each other:

```python
class EventBus:
    """Lightweight pub/sub for cross-view communication"""
    def __init__(self):
        self._handlers = defaultdict(list)

    def on(self, event_name, handler):
        self._handlers[event_name].append(handler)

    def emit(self, event_name, **kwargs):
        for handler in self._handlers[event_name]:
            handler(**kwargs)
```

**Events:**
- `process_selected(pid, name)` → String panel updates, network view filters
- `threat_detected(pid, rule, score)` → Badge updates, alert notification
- `ioc_extracted(type, value)` → Case view adds IOC
- `sigma_match(pid, rule_title, level)` → Live events highlights, badge update
- `network_suspicious(pid, remote_ip, reason)` → Process tree tag update
- `string_found_interesting(pid, string, category)` → Bookmarks/case notes

---

## Phase 3: Live Events Optimization

**Priority**: P1
**Goal**: Handle 50k+ events with timeline visualization and instant filtering

### Current Bottlenecks Identified
| Issue | Location | Impact |
|-------|----------|--------|
| TreeView limited to 5000 display rows | `MAD.py:2508-2513` | Old events silently discarded |
| 500ms refresh flicker | `MAD.py:2535` | Visible lag during high-event periods |
| No timeline visualization | N/A | Can't see event density patterns over time |
| No event bookmarking | N/A | Analysts lose track of important events |
| Linear event list | `MAD.py:2443-2452` | No process chain correlation |

### 3.1 Virtual Scrolling for Events TreeView (P1)

**File**: `views/live_events_view.py`

Same virtualization approach as the string table. Store all events in a Python list, only insert visible rows into the TreeView. This removes the 5000-row cap.

**Key difference from strings**: Events are append-only and arrive in real-time. The virtualizer needs an `append_batch()` method that adds new events without rebuilding the entire viewport:

```python
def append_events(self, new_events):
    """Add new events to the dataset — O(1) if user is scrolled to bottom"""
    self.all_data.extend(new_events)
    if self._is_scrolled_to_bottom():
        # User watching live — just append visible rows
        for event in new_events:
            if len(self.tree.get_children()) >= self._visible_count + self._buffer:
                # Remove oldest visible row
                self.tree.delete(self.tree.get_children()[0])
            self.tree.insert("", "end", values=self._format_event(event))
    # If scrolled up, don't disturb — user is reading history
```

### 3.2 Event Timeline Density Bar (P1)

**File**: `views/live_events_view.py`

A thin horizontal bar (30px tall) above the event list that shows event density over time using a histogram. Think "minimap" in a code editor.

```
┌─────────────────────────────────────────────────────────┐
│ ▁▂▃▅▇█▇▅▃▁▁▂▃▄▅▆▇████▇▆▅▄▃▂▁▁▁▁▁▂▃▄▅▆▇████████▇▅▃▂ │ ← density bar
│ 14:00        14:05        14:10        14:15      14:20  │ ← time labels
├─────────────────────────────────────────────────────────┤
│ Time    PID   Process   Type   Operation   Path   Result │
│ ...                                                       │
```

**Implementation**: Use a `tk.Canvas` widget. Divide the monitoring time range into N buckets (1 bucket per pixel width). Count events per bucket. Draw rectangles with height proportional to count. Color-code: grey=normal, red=suspicious, purple=sigma.

Clicking on a region of the timeline bar scrolls the event list to that time period.

### 3.3 Event Bookmarking / Pinning (P1)

Allow analysts to pin important events to a "bookmarks" panel:

- Right-click → "Bookmark This Event" or Ctrl+B
- Bookmarked events shown in a collapsible panel above the main event list
- Bookmarks persist for the session and can be exported with case notes
- Visual indicator (star icon) on bookmarked rows in the main list

### 3.4 Process Chain Correlation (P2)

**File**: `views/live_events_view.py`

When viewing events, highlight related event chains:

- Right-click a process event → "Show All Events for This Process Chain"
- Traces the parent→child PID chain and filters events to show only that lineage
- Useful for tracking: parent spawns child → child creates file → child makes network connection

### 3.5 Smart Refresh Strategy (P1)

**File**: `views/live_events_view.py`

Replace the fixed 500ms `after()` with adaptive refresh:

```python
def _adaptive_refresh(self):
    """Adjust refresh rate based on event volume"""
    pending = self._event_queue.qsize()

    if pending > 100:
        # High volume — batch process, refresh at 200ms
        self._process_batch(max_events=200)
        interval = 200
    elif pending > 10:
        # Medium volume — standard 500ms
        self._process_batch(max_events=50)
        interval = 500
    else:
        # Low volume — slow down to 1000ms to save CPU
        self._process_batch(max_events=pending)
        interval = 1000

    self._refresh_job = self.frame.after(interval, self._adaptive_refresh)
```

---

## Phase 4: Network Analysis

**Priority**: P1
**Goal**: Dedicated network visibility that lets analysts quickly identify C2, exfiltration, and lateral movement

### 4.1 Network Analysis Sub-Tab (P1)

**File**: `views/network_view.py` (new)

A dedicated third sub-tab under Analysis with four sections:

```
┌─────────────────────────────────────────────────────────┐
│ 🌐 Network Analysis    [⟳ Refresh]  [Export CSV]        │
├──────────────┬──────────────────────────────────────────┤
│ Summary      │ Connection Table                          │
│              │ ┌──────────────────────────────────────┐ │
│ Active: 42   │ │ PID | Process | Proto | Local | Rmt  │ │
│ Listening: 8 │ │     |         |       | Addr  | Addr │ │
│ Suspicious: 3│ │     |         |       |       | :Port│ │
│              │ │ ... |   ...   | ...   | ...   | ...  │ │
│ Top Talkers: │ └──────────────────────────────────────┘ │
│ chrome: 18   ├──────────────────────────────────────────┤
│ svchost: 9   │ DNS Queries                               │
│ malware: 4   │ ┌──────────────────────────────────────┐ │
│              │ │ Time | PID | Query | Response | TTL   │ │
│ Suspicious   │ │ ...  | ... | ...   | ...      | ...   │ │
│ Ports: 4444  │ └──────────────────────────────────────┘ │
└──────────────┴──────────────────────────────────────────┘
```

#### Connection Table
**Columns**: PID, Process, Protocol (TCP/UDP), State, Local Address, Remote Address, Remote Port, Hostname, Duration, Bytes (if available), Suspicious Flag

**Features:**
- Auto-refresh from `NetworkMonitor` data (1-second interval, matching existing)
- Color-coded rows: red=suspicious port/TLD, purple=known bad TLD, yellow=new connection
- Right-click context menu:
  - Copy Remote IP
  - Add Remote IP to Case IOCs
  - Resolve Hostname
  - Filter: Show only this PID
  - Filter: Show only this remote IP
  - Whois Lookup (opens browser)
- Column sorting (click headers)
- Filter bar: by PID, process name, remote IP, port, state, suspicious-only

#### DNS Query Log
**Data source**: `sysmon_parser.py` Event ID 22 (DNS Query) + `system_wide_monitor.py` DNS events

**Columns**: Timestamp, PID, Process, Query Name, Query Type, Response, TTL

**Features:**
- Highlight suspicious TLDs (from `SUSPICIOUS_TLDS` in `http_monitor.py`)
- Group repeated queries with count
- Right-click: Copy domain, Add to case, Filter by PID

#### Summary Panel (left sidebar within Network tab)
- Active connection count
- Listening port count
- Suspicious connection count (with details on hover)
- Top talkers: processes sorted by connection count
- Suspicious ports detected
- Unique remote IPs contacted
- Auto-updates on same refresh cycle as connection table

### 4.2 Optimize Existing HTTP Panel Under Processes (P1)

**File**: `views/process_view.py`

Per user direction: keep the HTTP panel under the process tree but scope it strictly to HTTP/HTTPS traffic.

**Changes:**
- Rename panel header to "HTTP/HTTPS Traffic" for clarity
- Filter out non-HTTP connections that may be leaking in
- Add hostname resolution caching (currently resolves every refresh cycle)
- Add response time column if measurable
- Add "Open in Network Tab" button that switches to Network sub-tab with PID pre-filtered
- Improve the session deduplication — currently uses `key = f"{pid}|{remote_ip}:{remote_port}"` which causes duplicates when connections cycle

### 4.3 Process-to-Network Correlation (P2)

**File**: `views/network_view.py` + `views/process_view.py`

When analyst selects a process in the tree:
- Network view automatically highlights all connections for that PID
- A connection count badge appears next to the process name in the tree (already partially implemented as the "Connections" column)

When analyst selects a connection in the Network view:
- Process tree scrolls to and highlights the owning process
- String quick-view can be triggered for the owning process

This bidirectional linking uses the EventBus from Phase 2.5.

### 4.4 Network Statistics Dashboard (P2)

**File**: `views/network_view.py`

Expandable statistics panel within the Network tab:

- **Connection Timeline**: Canvas widget showing new connections over time (similar to event density bar)
- **Port Distribution**: Top 10 remote ports with bar visualization
- **Geographic Summary**: If GeoIP integration added (optional), show country distribution
- **Protocol Breakdown**: TCP vs UDP vs HTTP vs HTTPS pie/bar
- **Data Volume**: Bytes sent/received per process (if available from psutil)

---

## Phase 5: Quality of Life & Polish

**Priority**: P2
**Goal**: Small improvements that compound into a significantly better analyst experience

### 5.1 Global Search / Command Palette (P2)

**Keyboard**: `Ctrl+K`

A floating search bar (similar to VS Code's command palette) that searches across:
- Process names and PIDs
- String extraction results (cached)
- IOCs in the current case
- YARA rule names
- Event data
- Network connections (remote IPs, hostnames)

Results grouped by category with keyboard navigation.

### 5.2 Status Bar (P1)

A persistent bottom bar showing real-time system state:

```
┌────────────────────────────────────────────────────────────────┐
│ Monitoring: Active | Processes: 142 | Events: 12,847 |        │
│ Network: 42 active | HTTP: 8 sessions | YARA: 3 threats |     │
│ Sigma: 1 match | CPU: 2.1% | Mem: 48MB                        │
└────────────────────────────────────────────────────────────────┘
```

This gives analysts constant awareness of the monitoring state without switching tabs.

### 5.3 Toast Notifications (P2)

Non-blocking notification toasts for critical events:
- New YARA match detected
- New Sigma rule match
- Suspicious network connection detected
- Persistence mechanism detected

Toasts appear in the top-right corner, auto-dismiss after 5 seconds, clickable to navigate to the relevant view.

### 5.4 Process Tree Performance (P1)

**File**: `views/process_view.py`

Current issues with process tree refresh:
- `psutil.Process(pid).status()` called for EVERY process on EVERY refresh (lines 5461-5466) — expensive
- Sigma evaluation runs for every process on every refresh (line 5497) — expensive
- `_get_process_connections_summary(pid)` called per-process per-refresh — network I/O

**Optimizations:**
1. Batch `psutil.process_iter()` call instead of per-PID `psutil.Process()` — single system call vs N calls
2. Cache Sigma evaluation results per PID with invalidation on rule change
3. Cache connection summaries with 2-second TTL (connections don't change that fast)
4. Only re-evaluate Sigma for processes whose `exe` or `cmdline` changed since last check
5. Reduce the per-process status check to only run for processes that are in the visible viewport

---

## Implementation Order (Recommended)

```
Phase 0 (Foundation)
  └── 0.1 Modularize MAD.py into view modules
       │
Phase 1 (Strings) ─────────────────── Phase 2 (Layout) ──── Phase 3 (Events)
  ├── 1.1 Virtualized String Table     ├── 2.1 Keyboard       ├── 3.1 Virtual scroll
  ├── 1.2 Dual-mode panel              │       shortcuts       ├── 3.5 Smart refresh
  ├── 1.3 Extractor performance        ├── 2.2 3-tab analysis ├── 3.2 Timeline bar
  └── 1.4 Category classification      ├── 2.3 Split-pane     ├── 3.3 Bookmarking
                                        ├── 2.5 Event bus      └── 3.4 Chain correlation
                                        └── 2.4 Breadcrumbs
                                             │
                                        Phase 4 (Network)
                                          ├── 4.1 Network tab
                                          ├── 4.2 HTTP panel optimize
                                          ├── 4.3 Process↔Network correlation
                                          └── 4.4 Statistics dashboard
                                             │
                                        Phase 5 (Polish)
                                          ├── 5.1 Command palette
                                          ├── 5.2 Status bar
                                          ├── 5.3 Toast notifications
                                          └── 5.4 Process tree perf
```

**Dependencies:**
- Phase 0 must complete before Phases 1-4 (modularization enables parallel development)
- Phase 2.5 (Event Bus) must complete before Phase 4.3 (cross-view correlation)
- Phase 2.2 (3-tab analysis) must complete before Phase 4.1 (network tab)
- Phase 1.1 (virtualized table) should complete before Phase 3.1 (same pattern reused for events)

**Phases 1, 2, and 3 can largely proceed in parallel** after Phase 0 completes, since they target different view modules.

---

## Performance Targets

| Metric | Current | Target |
|--------|---------|--------|
| String display limit | 1,000 | 500,000+ |
| String extraction limit | 20,000 | 500,000 |
| Time to show strings after process click | 3-5 seconds | <500ms (cached), <2s (fresh quick scan) |
| Live events display limit | 5,000 | 100,000+ |
| Event refresh interval | Fixed 500ms | Adaptive 200-1000ms |
| Process tree refresh overhead | O(N) per-PID API calls | O(1) batch call |
| Keyboard shortcuts | 0 | 20+ |
| Tab navigation clicks to reach strings | 3 (tab → process → popup) | 1 (select process, inline panel appears) |
| Network analysis | No dedicated view | Full tab with connections + DNS |

---

## Files Created / Modified Summary

### New Files
```
views/__init__.py
views/base_view.py
views/shared_widgets.py
views/new_case_view.py
views/current_case_view.py
views/process_view.py
views/live_events_view.py
views/network_view.py
views/string_analysis_view.py
views/yara_rules_view.py
views/settings_view.py
```

### Modified Files
```
MAD.py                                    (8660 → ~800 lines, app shell only)
analysis_modules/memory_string_extractor.py  (hex offsets, parallel scanning, no extraction limit)
analysis_modules/network_monitor.py          (batch connection retrieval, DNS event integration)
analysis_modules/http_monitor.py             (hostname cache, session dedup fix)
analysis_modules/system_wide_monitor.py      (event bus integration)
```

### Unchanged Files
```
case_manager.py                   (no changes needed)
settings_manager.py               (no changes needed)
sigma_rule_manager.py             (no changes needed)
yara_rule_manager.py              (no changes needed)
analysis_modules/sigma_evaluator.py         (no changes needed)
analysis_modules/process_monitor.py         (minor: expose batch process list)
analysis_modules/sysmon_parser.py           (no changes needed)
analysis_modules/persistence_monitor.py     (no changes needed)
analysis_modules/process_activity_monitor.py (no changes needed)
```
