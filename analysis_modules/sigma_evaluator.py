"""
Sigma Rule Evaluator - In-memory evaluation of Sigma rules against Sysmon/system events

Evaluates structured event dictionaries against loaded Sigma detection rules.
Sigma rules use YAML format with logsource, detection, and condition sections.

Field names in Sigma rules map directly to Sysmon event field names (Image, CommandLine,
ParentImage, TargetFilename, DestinationPort, etc.) which are already present in
SysmonEvent.raw_data.

References:
- Sigma specification: https://github.com/SigmaHQ/sigma-specification
- SigmaHQ rules: https://github.com/SigmaHQ/sigma
"""

import os
import re
import fnmatch
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Tuple

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    print("Warning: PyYAML not available. Sigma rule evaluation will be disabled.")
    print("Install with: pip install pyyaml")


class SigmaRule:
    """Represents a parsed Sigma detection rule"""

    def __init__(self, rule_data: Dict[str, Any], file_path: str = ""):
        self.file_path = file_path
        self.raw = rule_data

        # Metadata
        self.id = rule_data.get('id', '')
        self.title = rule_data.get('title', 'Untitled Rule')
        self.description = rule_data.get('description', '')
        self.status = rule_data.get('status', 'experimental')
        self.level = rule_data.get('level', 'medium')  # informational, low, medium, high, critical
        self.author = rule_data.get('author', '')
        self.date = rule_data.get('date', '')
        self.tags = rule_data.get('tags', [])
        self.references = rule_data.get('references', [])
        self.falsepositives = rule_data.get('falsepositives', [])

        # Logsource
        self.logsource = rule_data.get('logsource', {})
        self.category = self.logsource.get('category', '')
        self.product = self.logsource.get('product', 'windows')
        self.service = self.logsource.get('service', '')

        # Detection
        self.detection = rule_data.get('detection', {})
        self.condition = self.detection.get('condition', '')

    def __repr__(self):
        return f"SigmaRule(title='{self.title}', level='{self.level}')"


class SigmaMatch:
    """Represents a Sigma rule match against an event"""

    def __init__(self, rule: SigmaRule, event_data: Dict[str, Any], matched_selections: List[str]):
        self.rule = rule
        self.event_data = event_data
        self.matched_selections = matched_selections
        self.timestamp = datetime.now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'rule_title': self.rule.title,
            'rule_id': self.rule.id,
            'rule_level': self.rule.level,
            'rule_description': self.rule.description,
            'rule_tags': self.rule.tags,
            'rule_file': self.rule.file_path,
            'matched_selections': self.matched_selections,
            'timestamp': self.timestamp.isoformat(),
        }


class SigmaEvaluator:
    """
    Evaluates events against loaded Sigma rules in-memory.

    Works with dictionaries keyed by Sysmon field names (Image, CommandLine, etc.)
    as found in SysmonEvent.raw_data, or mapped from psutil fallback events.
    """

    # Maps Sigma logsource category to Sysmon Event IDs
    CATEGORY_TO_EVENT_IDS = {
        'process_creation': [1],
        'process_termination': [5],
        'network_connection': [3],
        'image_load': [7],
        'file_event': [11, 15, 23, 26],
        'file_creation': [11],
        'file_change': [2],
        'file_delete': [23, 26],
        'file_access': [11],
        'registry_event': [12, 13, 14],
        'registry_add': [12],
        'registry_set': [13],
        'registry_rename': [14],
        'dns_query': [22],
        'process_access': [10],
        'driver_load': [6],
        'create_remote_thread': [8],
        'pipe_created': [17],
        'pipe_connected': [18],
        'wmi_event': [19, 20, 21],
        'clipboard_capture': [24],
        'process_tampering': [25],
    }

    # Maps simplified event_type (from to_dict) back to Sigma categories
    EVENT_TYPE_TO_CATEGORIES = {
        'Process': ['process_creation', 'process_termination', 'process_access', 'process_tampering'],
        'File': ['file_event', 'file_creation', 'file_change', 'file_delete', 'file_access'],
        'Network': ['network_connection'],
        'Registry': ['registry_event', 'registry_add', 'registry_set', 'registry_rename'],
        'DNS': ['dns_query'],
        'ImageLoad': ['image_load', 'driver_load'],
        'Thread': ['create_remote_thread'],
        'Pipe': ['pipe_created', 'pipe_connected'],
        'WMI': ['wmi_event'],
        'Clipboard': ['clipboard_capture'],
    }

    # Maps psutil fallback event fields to Sigma/Sysmon field names
    # Order matters: 'path' has full exe path so it takes priority over 'process_name'
    PSUTIL_FIELD_MAP = [
        ('path', 'Image'),
        ('detail', 'CommandLine'),
    ]

    def __init__(self):
        self.rules: List[SigmaRule] = []
        self.rules_by_category: Dict[str, List[SigmaRule]] = {}
        self._match_callbacks = []
        self.stats = {
            'rules_loaded': 0,
            'events_evaluated': 0,
            'matches_found': 0,
            'errors': 0,
        }
        # Minimum severity level filter
        self._min_level = 'low'
        self._level_order = {
            'informational': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4
        }

    def set_min_level(self, level: str):
        """Set minimum severity level for rule evaluation"""
        if level.lower() in self._level_order:
            self._min_level = level.lower()

    def get_min_level(self) -> str:
        return self._min_level

    def register_match_callback(self, callback):
        """Register callback for when a rule matches. callback(SigmaMatch)"""
        self._match_callbacks.append(callback)

    def load_rules_from_directory(self, rules_dir: str) -> Tuple[int, List[str]]:
        """
        Load all Sigma rules (.yml/.yaml) from a directory.

        Returns:
            Tuple of (rules_loaded_count, list_of_error_messages)
        """
        if not YAML_AVAILABLE:
            return 0, ["PyYAML not installed"]

        rules_path = Path(rules_dir)
        if not rules_path.exists():
            return 0, [f"Directory not found: {rules_dir}"]

        loaded = 0
        errors = []

        for yml_file in sorted(rules_path.glob("*.yml")):
            success, err = self._load_rule_file(str(yml_file))
            if success:
                loaded += 1
            elif err:
                errors.append(err)

        for yaml_file in sorted(rules_path.glob("*.yaml")):
            success, err = self._load_rule_file(str(yaml_file))
            if success:
                loaded += 1
            elif err:
                errors.append(err)

        self.stats['rules_loaded'] = len(self.rules)
        return loaded, errors

    def load_rule_from_string(self, yaml_content: str, file_path: str = "<string>") -> Tuple[bool, str]:
        """Load a single Sigma rule from YAML string content."""
        if not YAML_AVAILABLE:
            return False, "PyYAML not installed"

        try:
            rule_data = yaml.safe_load(yaml_content)
            if not isinstance(rule_data, dict):
                return False, "YAML content is not a valid Sigma rule (not a dict)"
            return self._add_rule(rule_data, file_path)
        except yaml.YAMLError as e:
            return False, f"YAML parse error: {e}"

    def _load_rule_file(self, file_path: str) -> Tuple[bool, str]:
        """Load a single rule file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_data = yaml.safe_load(f)

            if not isinstance(rule_data, dict):
                return False, f"{file_path}: Not a valid Sigma rule (not a dict)"

            return self._add_rule(rule_data, file_path)

        except yaml.YAMLError as e:
            return False, f"{file_path}: YAML error: {e}"
        except Exception as e:
            return False, f"{file_path}: {e}"

    def _add_rule(self, rule_data: Dict, file_path: str) -> Tuple[bool, str]:
        """Validate and add a rule."""
        # Must have detection and logsource
        if 'detection' not in rule_data:
            return False, f"{file_path}: Missing 'detection' section"
        if 'logsource' not in rule_data:
            return False, f"{file_path}: Missing 'logsource' section"
        detection = rule_data['detection']
        if 'condition' not in detection:
            return False, f"{file_path}: Missing 'condition' in detection"

        rule = SigmaRule(rule_data, file_path)

        # Check minimum level
        rule_level = self._level_order.get(rule.level, 2)
        min_level = self._level_order.get(self._min_level, 1)
        if rule_level < min_level:
            return True, ""  # Skipped due to level filter, not an error

        self.rules.append(rule)
        self.stats['rules_loaded'] = len(self.rules)

        # Index by category for fast lookup
        category = rule.category
        if category:
            if category not in self.rules_by_category:
                self.rules_by_category[category] = []
            self.rules_by_category[category].append(rule)

        return True, ""

    def reload_rules(self, rules_dir: str) -> Tuple[int, List[str]]:
        """Clear all rules and reload from directory."""
        self.rules.clear()
        self.rules_by_category.clear()
        return self.load_rules_from_directory(rules_dir)

    def evaluate_sysmon_event(self, sysmon_event) -> List[SigmaMatch]:
        """
        Evaluate a SysmonEvent object against all loaded rules.

        Args:
            sysmon_event: SysmonEvent instance (has .event_id, .raw_data)

        Returns:
            List of SigmaMatch for each rule that matched
        """
        event_id = sysmon_event.event_id
        raw_data = sysmon_event.raw_data

        return self._evaluate(raw_data, event_id)

    def evaluate_event_dict(self, event_dict: Dict[str, Any], event_id: Optional[int] = None) -> List[SigmaMatch]:
        """
        Evaluate a standard event dictionary against all loaded rules.

        For psutil fallback events, maps field names to Sigma/Sysmon field names.

        Args:
            event_dict: Event dictionary (from to_dict() or psutil)
            event_id: Sysmon event ID if known, otherwise inferred from event_type

        Returns:
            List of SigmaMatch for each rule that matched
        """
        # If we have raw_data embedded, use it directly
        if 'raw_data' in event_dict:
            return self._evaluate(event_dict['raw_data'], event_id or event_dict.get('event_id'))

        # For psutil fallback events, build a Sigma-compatible field dict
        sigma_fields = {}
        for psutil_key, sigma_key in self.PSUTIL_FIELD_MAP:
            if psutil_key in event_dict and event_dict[psutil_key]:
                # Don't overwrite if already set (first mapping wins)
                if sigma_key not in sigma_fields:
                    sigma_fields[sigma_key] = str(event_dict[psutil_key])

        # Map operation to event_id if not provided
        if event_id is None:
            event_id = event_dict.get('event_id')
        if event_id is None:
            op = event_dict.get('operation', '')
            op_to_id = {
                'ProcessCreate': 1, 'ProcessTerminate': 5,
                'NetworkConnect': 3, 'LoadImage': 7,
                'CreateFile': 11, 'FileDelete': 23,
                'RegCreateKey': 12, 'RegSetValue': 13, 'RegRenameKey': 14,
                'DNSQuery': 22,
            }
            event_id = op_to_id.get(op)

        # For process creation from psutil, parse the detail field for CommandLine
        if event_dict.get('operation') == 'ProcessCreate' and event_dict.get('detail'):
            detail = event_dict['detail']
            if detail.startswith('Command: '):
                sigma_fields['CommandLine'] = detail[9:]

        return self._evaluate(sigma_fields, event_id)

    def _evaluate(self, event_data: Dict[str, Any], event_id: Optional[int] = None) -> List[SigmaMatch]:
        """Core evaluation: check event_data against all applicable rules."""
        self.stats['events_evaluated'] += 1
        matches = []

        # Get candidate rules based on event_id
        candidate_rules = self._get_candidate_rules(event_id)

        for rule in candidate_rules:
            try:
                matched_selections = self._evaluate_rule(rule, event_data)
                if matched_selections:
                    match = SigmaMatch(rule, event_data, matched_selections)
                    matches.append(match)
                    self.stats['matches_found'] += 1

                    # Notify callbacks
                    for callback in self._match_callbacks:
                        try:
                            callback(match)
                        except Exception as e:
                            print(f"Error in sigma match callback: {e}")

            except Exception as e:
                self.stats['errors'] += 1

        return matches

    def _get_candidate_rules(self, event_id: Optional[int]) -> List[SigmaRule]:
        """Get rules that could match based on event_id."""
        if event_id is None:
            return self.rules  # Can't filter, check all

        candidates = []
        for rule in self.rules:
            if self._rule_matches_event_id(rule, event_id):
                candidates.append(rule)

        return candidates

    def _rule_matches_event_id(self, rule: SigmaRule, event_id: int) -> bool:
        """Check if a rule's logsource could match the given event ID."""
        category = rule.category
        if not category:
            return True  # No category filter, could match anything

        valid_ids = self.CATEGORY_TO_EVENT_IDS.get(category, [])
        if not valid_ids:
            return True  # Unknown category, don't filter out

        return event_id in valid_ids

    def _evaluate_rule(self, rule: SigmaRule, event_data: Dict) -> List[str]:
        """
        Evaluate a single rule's detection section against event data.

        Returns list of matched selection names, or empty list if no match.
        """
        detection = rule.detection
        condition = detection.get('condition', '')

        # Extract named selections (everything except 'condition' and 'timeframe')
        selections = {}
        for key, value in detection.items():
            if key not in ('condition', 'timeframe'):
                selections[key] = value

        # Evaluate each selection
        selection_results = {}
        for sel_name, sel_def in selections.items():
            selection_results[sel_name] = self._evaluate_selection(sel_def, event_data)

        # Evaluate condition
        if self._evaluate_condition(condition, selection_results):
            return [name for name, result in selection_results.items() if result]

        return []

    def _evaluate_selection(self, selection_def: Any, event_data: Dict) -> bool:
        """
        Evaluate a single selection definition against event data.

        Selection can be:
        - Dict of {field: value} or {field|modifier: value} → all must match (AND)
        - List of dicts → any dict must match (OR)
        - List of values (for a single field) → any value must match (OR)
        """
        if isinstance(selection_def, dict):
            return self._evaluate_selection_dict(selection_def, event_data)
        elif isinstance(selection_def, list):
            # List of dicts = OR
            if all(isinstance(item, dict) for item in selection_def):
                return any(self._evaluate_selection_dict(item, event_data) for item in selection_def)
            # Shouldn't normally happen at selection level
            return False
        return False

    def _evaluate_selection_dict(self, selection: Dict, event_data: Dict) -> bool:
        """
        Evaluate a selection dictionary. All fields must match (AND logic).

        Supports Sigma modifiers:
        - field|endswith: value
        - field|startswith: value
        - field|contains: value
        - field|all: [values]  (all values must be present)
        - field|re: regex
        """
        for field_spec, expected_values in selection.items():
            field_name, modifiers = self._parse_field_spec(field_spec)

            # Get the actual field value from event data (case-insensitive lookup)
            actual_value = self._get_field_value(event_data, field_name)

            if actual_value is None:
                # Field not present in event - no match
                return False

            actual_str = str(actual_value)

            # Normalize expected_values to a list
            if not isinstance(expected_values, list):
                expected_values = [expected_values]

            # Handle 'all' modifier: every value must match
            if 'all' in modifiers:
                if not all(self._match_single_value(actual_str, ev, modifiers) for ev in expected_values):
                    return False
            else:
                # Default OR logic: at least one value must match
                if not any(self._match_single_value(actual_str, ev, modifiers) for ev in expected_values):
                    return False

        return True

    def _parse_field_spec(self, field_spec: str) -> Tuple[str, List[str]]:
        """Parse 'field|modifier1|modifier2' into (field_name, [modifiers])."""
        parts = field_spec.split('|')
        return parts[0], parts[1:]

    def _get_field_value(self, event_data: Dict, field_name: str) -> Optional[str]:
        """Get field value from event data with case-insensitive key matching."""
        # Direct lookup first
        if field_name in event_data:
            return event_data[field_name]

        # Case-insensitive fallback
        field_lower = field_name.lower()
        for key, value in event_data.items():
            if key.lower() == field_lower:
                return value

        return None

    def _match_single_value(self, actual: str, expected: Any, modifiers: List[str]) -> bool:
        """Match a single actual value against a single expected value with modifiers."""
        if expected is None:
            return actual is None or actual == ''

        expected_str = str(expected)
        actual_lower = actual.lower()
        expected_lower = expected_str.lower()

        # Apply modifiers
        if 're' in modifiers:
            try:
                return bool(re.search(expected_str, actual, re.IGNORECASE))
            except re.error:
                return False

        if 'startswith' in modifiers:
            return actual_lower.startswith(expected_lower)

        if 'endswith' in modifiers:
            return actual_lower.endswith(expected_lower)

        if 'contains' in modifiers:
            return expected_lower in actual_lower

        # Default: wildcard match (Sigma uses * as wildcard)
        if '*' in expected_str or '?' in expected_str:
            return self._wildcard_match(actual, expected_str)

        # Exact match (case-insensitive)
        return actual_lower == expected_lower

    def _wildcard_match(self, value: str, pattern: str) -> bool:
        """Match value against a Sigma wildcard pattern (* and ?)."""
        # Convert Sigma wildcards to fnmatch pattern (already uses * and ?)
        # fnmatch is case-sensitive on Linux, so normalize
        return fnmatch.fnmatch(value.lower(), pattern.lower())

    def _evaluate_condition(self, condition: str, selection_results: Dict[str, bool]) -> bool:
        """
        Evaluate a Sigma condition string against selection results.

        Supports:
        - selection_name (direct reference)
        - selection1 and selection2
        - selection1 or selection2
        - not selection1
        - 1 of selection_*
        - all of selection_*
        - 1 of them
        - all of them
        - Parentheses for grouping
        """
        condition = condition.strip()

        # Handle "X of them" / "X of selection_*"
        of_match = re.match(r'^(all|\d+)\s+of\s+(them|[\w*]+)$', condition, re.IGNORECASE)
        if of_match:
            count_str = of_match.group(1)
            target = of_match.group(2)
            return self._evaluate_of(count_str, target, selection_results)

        # Tokenize and evaluate boolean expression
        return self._eval_bool_expr(condition, selection_results)

    def _evaluate_of(self, count_str: str, target: str, selection_results: Dict[str, bool]) -> bool:
        """Evaluate 'X of target' expressions."""
        # Get matching selections
        if target.lower() == 'them':
            matching_sels = list(selection_results.values())
        elif '*' in target:
            pattern = target.replace('*', '.*')
            matching_sels = [
                v for k, v in selection_results.items()
                if re.match(pattern, k, re.IGNORECASE)
            ]
        else:
            matching_sels = [selection_results.get(target, False)]

        true_count = sum(1 for s in matching_sels if s)

        if count_str.lower() == 'all':
            return len(matching_sels) > 0 and true_count == len(matching_sels)
        else:
            required = int(count_str)
            return true_count >= required

    def _eval_bool_expr(self, expr: str, selection_results: Dict[str, bool]) -> bool:
        """Evaluate a boolean expression with and/or/not and parentheses."""
        expr = expr.strip()

        # Handle parentheses first
        while '(' in expr:
            # Find innermost parentheses
            match = re.search(r'\(([^()]+)\)', expr)
            if not match:
                break
            inner_result = self._eval_bool_expr(match.group(1), selection_results)
            placeholder = f"__RESULT_{id(match)}__"
            selection_results[placeholder] = inner_result
            expr = expr[:match.start()] + placeholder + expr[match.end():]

        # Handle "X of" within boolean expressions
        of_match = re.search(r'(all|\d+)\s+of\s+(them|[\w*]+)', expr, re.IGNORECASE)
        if of_match:
            of_result = self._evaluate_of(of_match.group(1), of_match.group(2), selection_results)
            placeholder = f"__OF_{id(of_match)}__"
            selection_results[placeholder] = of_result
            expr = expr[:of_match.start()] + placeholder + expr[of_match.end():]

        # Split by 'or' (lowest precedence)
        or_parts = re.split(r'\s+or\s+', expr, flags=re.IGNORECASE)
        if len(or_parts) > 1:
            return any(self._eval_bool_expr(part, selection_results) for part in or_parts)

        # Split by 'and'
        and_parts = re.split(r'\s+and\s+', expr, flags=re.IGNORECASE)
        if len(and_parts) > 1:
            return all(self._eval_bool_expr(part, selection_results) for part in and_parts)

        # Handle 'not'
        expr = expr.strip()
        not_match = re.match(r'^not\s+(.+)$', expr, re.IGNORECASE)
        if not_match:
            return not self._eval_bool_expr(not_match.group(1), selection_results)

        # Direct selection reference
        sel_name = expr.strip()
        return selection_results.get(sel_name, False)

    def get_stats(self) -> Dict[str, Any]:
        return self.stats.copy()

    def get_rules(self) -> List[SigmaRule]:
        return list(self.rules)

    def get_rules_by_level(self, level: str) -> List[SigmaRule]:
        target = self._level_order.get(level.lower(), 2)
        return [r for r in self.rules if self._level_order.get(r.level, 2) == target]

    def get_rule_count(self) -> int:
        return len(self.rules)
