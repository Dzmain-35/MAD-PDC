"""
Tests for the Sigma Rule Evaluator

Tests cover:
- YAML parsing and rule loading
- Field matching (exact, wildcard, modifiers)
- Condition evaluation (and, or, not, X of)
- Logsource-to-event-id mapping
- Full rule evaluation against simulated events
- SigmaRuleManager validation
"""

import os
import sys
import tempfile
import shutil
import unittest

# Add project root to path so we can import modules directly
PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, PROJECT_ROOT)

# Import sigma_evaluator directly via importlib.util to avoid __init__.py
# pulling in yara/wmi/win32 dependencies that aren't available in test environments
import importlib.util

_sigma_spec = importlib.util.spec_from_file_location(
    "sigma_evaluator",
    os.path.join(PROJECT_ROOT, "analysis_modules", "sigma_evaluator.py")
)
_sigma_mod = importlib.util.module_from_spec(_sigma_spec)
_sigma_spec.loader.exec_module(_sigma_mod)
SigmaEvaluator = _sigma_mod.SigmaEvaluator
SigmaRule = _sigma_mod.SigmaRule
SigmaMatch = _sigma_mod.SigmaMatch

from sigma_rule_manager import SigmaRuleManager


class TestSigmaFieldMatching(unittest.TestCase):
    """Test individual field value matching logic"""

    def setUp(self):
        self.evaluator = SigmaEvaluator()

    def test_exact_match(self):
        result = self.evaluator._match_single_value(
            r'C:\Windows\System32\cmd.exe', r'C:\Windows\System32\cmd.exe', []
        )
        self.assertTrue(result)

    def test_exact_match_case_insensitive(self):
        result = self.evaluator._match_single_value(
            r'C:\Windows\System32\CMD.EXE', r'c:\windows\system32\cmd.exe', []
        )
        self.assertTrue(result)

    def test_exact_match_fail(self):
        result = self.evaluator._match_single_value(
            r'C:\Windows\System32\cmd.exe', r'C:\Windows\System32\powershell.exe', []
        )
        self.assertFalse(result)

    def test_wildcard_endswith(self):
        result = self.evaluator._match_single_value(
            r'C:\Windows\System32\cmd.exe', r'*\cmd.exe', []
        )
        self.assertTrue(result)

    def test_wildcard_contains(self):
        result = self.evaluator._match_single_value(
            r'C:\Windows\System32\cmd.exe /c whoami', r'*cmd.exe*', []
        )
        self.assertTrue(result)

    def test_wildcard_startswith(self):
        result = self.evaluator._match_single_value(
            r'C:\Windows\System32\cmd.exe', r'C:\Windows\*', []
        )
        self.assertTrue(result)

    def test_wildcard_fail(self):
        result = self.evaluator._match_single_value(
            r'C:\Users\test\malware.exe', r'*\cmd.exe', []
        )
        self.assertFalse(result)

    def test_contains_modifier(self):
        result = self.evaluator._match_single_value(
            'powershell.exe -enc ABC123', '-enc', ['contains']
        )
        self.assertTrue(result)

    def test_contains_modifier_fail(self):
        result = self.evaluator._match_single_value(
            'powershell.exe -version', '-enc', ['contains']
        )
        self.assertFalse(result)

    def test_startswith_modifier(self):
        result = self.evaluator._match_single_value(
            r'C:\Windows\System32\cmd.exe', r'C:\Windows', ['startswith']
        )
        self.assertTrue(result)

    def test_endswith_modifier(self):
        result = self.evaluator._match_single_value(
            r'C:\Windows\System32\cmd.exe', r'\cmd.exe', ['endswith']
        )
        self.assertTrue(result)

    def test_re_modifier(self):
        result = self.evaluator._match_single_value(
            'powershell.exe -enc AAAA', r'-e(nc|ncodedcommand)', ['re']
        )
        self.assertTrue(result)

    def test_re_modifier_fail(self):
        result = self.evaluator._match_single_value(
            'powershell.exe -version', r'-e(nc|ncodedcommand)', ['re']
        )
        self.assertFalse(result)


class TestSigmaSelectionEvaluation(unittest.TestCase):
    """Test selection dict evaluation (AND logic, field lookups)"""

    def setUp(self):
        self.evaluator = SigmaEvaluator()

    def test_single_field_match(self):
        selection = {'Image': r'*\powershell.exe'}
        event = {'Image': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'}
        self.assertTrue(self.evaluator._evaluate_selection_dict(selection, event))

    def test_multi_field_and_logic(self):
        """All fields must match in a single selection dict"""
        selection = {
            'Image|endswith': r'\powershell.exe',
            'CommandLine|contains': '-enc'
        }
        event = {
            'Image': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            'CommandLine': 'powershell.exe -enc SGVsbG8='
        }
        self.assertTrue(self.evaluator._evaluate_selection_dict(selection, event))

    def test_multi_field_and_one_fails(self):
        """If one field doesn't match, entire selection fails"""
        selection = {
            'Image|endswith': r'\powershell.exe',
            'CommandLine|contains': '-enc'
        }
        event = {
            'Image': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            'CommandLine': 'powershell.exe -version'
        }
        self.assertFalse(self.evaluator._evaluate_selection_dict(selection, event))

    def test_field_with_multiple_values_or_logic(self):
        """Multiple values for a field = OR logic"""
        selection = {
            'Image|endswith': [r'\powershell.exe', r'\pwsh.exe']
        }
        event = {'Image': r'C:\Program Files\PowerShell\7\pwsh.exe'}
        self.assertTrue(self.evaluator._evaluate_selection_dict(selection, event))

    def test_field_with_all_modifier(self):
        """'all' modifier: every value must be found"""
        selection = {
            'CommandLine|contains|all': ['-enc', '-nop']
        }
        event = {'CommandLine': 'powershell.exe -nop -enc AAAA'}
        self.assertTrue(self.evaluator._evaluate_selection_dict(selection, event))

    def test_field_with_all_modifier_one_missing(self):
        selection = {
            'CommandLine|contains|all': ['-enc', '-nop']
        }
        event = {'CommandLine': 'powershell.exe -enc AAAA'}
        self.assertFalse(self.evaluator._evaluate_selection_dict(selection, event))

    def test_missing_field_no_match(self):
        selection = {'CommandLine|contains': '-enc'}
        event = {'Image': r'C:\cmd.exe'}  # No CommandLine field
        self.assertFalse(self.evaluator._evaluate_selection_dict(selection, event))

    def test_case_insensitive_field_lookup(self):
        """Field names should match case-insensitively"""
        selection = {'image|endswith': r'\cmd.exe'}
        event = {'Image': r'C:\Windows\System32\cmd.exe'}
        self.assertTrue(self.evaluator._evaluate_selection_dict(selection, event))


class TestSigmaConditionEvaluation(unittest.TestCase):
    """Test condition string parsing and evaluation"""

    def setUp(self):
        self.evaluator = SigmaEvaluator()

    def test_single_selection(self):
        results = {'selection': True}
        self.assertTrue(self.evaluator._evaluate_condition('selection', results))

    def test_and_condition(self):
        results = {'sel1': True, 'sel2': True}
        self.assertTrue(self.evaluator._evaluate_condition('sel1 and sel2', results))

    def test_and_condition_fail(self):
        results = {'sel1': True, 'sel2': False}
        self.assertFalse(self.evaluator._evaluate_condition('sel1 and sel2', results))

    def test_or_condition(self):
        results = {'sel1': False, 'sel2': True}
        self.assertTrue(self.evaluator._evaluate_condition('sel1 or sel2', results))

    def test_or_condition_fail(self):
        results = {'sel1': False, 'sel2': False}
        self.assertFalse(self.evaluator._evaluate_condition('sel1 or sel2', results))

    def test_not_condition(self):
        results = {'selection': True, 'filter': False}
        self.assertTrue(self.evaluator._evaluate_condition('selection and not filter', results))

    def test_not_condition_filtered(self):
        results = {'selection': True, 'filter': True}
        self.assertFalse(self.evaluator._evaluate_condition('selection and not filter', results))

    def test_1_of_them(self):
        results = {'sel1': False, 'sel2': True, 'sel3': False}
        self.assertTrue(self.evaluator._evaluate_condition('1 of them', results))

    def test_all_of_them(self):
        results = {'sel1': True, 'sel2': True}
        self.assertTrue(self.evaluator._evaluate_condition('all of them', results))

    def test_all_of_them_fail(self):
        results = {'sel1': True, 'sel2': False}
        self.assertFalse(self.evaluator._evaluate_condition('all of them', results))

    def test_1_of_selection_wildcard(self):
        results = {'selection_img': True, 'selection_cmd': False, 'filter': False}
        self.assertTrue(self.evaluator._evaluate_condition('1 of selection_*', results))


class TestSigmaRuleLoading(unittest.TestCase):
    """Test loading rules from YAML content and files"""

    def setUp(self):
        self.evaluator = SigmaEvaluator()
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_load_rule_from_string(self):
        rule_yaml = """
title: Test Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
level: high
"""
        success, err = self.evaluator.load_rule_from_string(rule_yaml)
        self.assertTrue(success, f"Failed to load rule: {err}")
        self.assertEqual(self.evaluator.get_rule_count(), 1)

    def test_load_rule_missing_detection(self):
        rule_yaml = """
title: Bad Rule
logsource:
    category: process_creation
"""
        success, err = self.evaluator.load_rule_from_string(rule_yaml)
        self.assertFalse(success)
        self.assertIn('detection', err)

    def test_load_rule_missing_condition(self):
        rule_yaml = """
title: Bad Rule
logsource:
    category: process_creation
detection:
    selection:
        Image: cmd.exe
"""
        success, err = self.evaluator.load_rule_from_string(rule_yaml)
        self.assertFalse(success)
        self.assertIn('condition', err)

    def test_load_rules_from_directory(self):
        # Write two rules
        for i in range(3):
            rule_yaml = f"""
title: Test Rule {i}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
level: high
"""
            with open(os.path.join(self.test_dir, f"rule_{i}.yml"), 'w') as f:
                f.write(rule_yaml)

        loaded, errors = self.evaluator.load_rules_from_directory(self.test_dir)
        self.assertEqual(loaded, 3)
        self.assertEqual(len(errors), 0)
        self.assertEqual(self.evaluator.get_rule_count(), 3)

    def test_level_filtering(self):
        """Rules below minimum level should be skipped"""
        self.evaluator.set_min_level('high')

        low_rule = """
title: Low Rule
logsource:
    category: process_creation
detection:
    selection:
        Image: cmd.exe
    condition: selection
level: low
"""
        high_rule = """
title: High Rule
logsource:
    category: process_creation
detection:
    selection:
        Image: cmd.exe
    condition: selection
level: high
"""
        self.evaluator.load_rule_from_string(low_rule)
        self.evaluator.load_rule_from_string(high_rule)
        # Only the high rule should be loaded
        self.assertEqual(self.evaluator.get_rule_count(), 1)
        self.assertEqual(self.evaluator.get_rules()[0].title, 'High Rule')


class TestSigmaLogsourceMapping(unittest.TestCase):
    """Test that logsource categories map correctly to event IDs"""

    def setUp(self):
        self.evaluator = SigmaEvaluator()

    def test_process_creation_matches_event_1(self):
        rule_yaml = """
title: Test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
level: high
"""
        self.evaluator.load_rule_from_string(rule_yaml)
        rule = self.evaluator.get_rules()[0]

        self.assertTrue(self.evaluator._rule_matches_event_id(rule, 1))
        self.assertFalse(self.evaluator._rule_matches_event_id(rule, 3))
        self.assertFalse(self.evaluator._rule_matches_event_id(rule, 11))

    def test_network_connection_matches_event_3(self):
        rule_yaml = """
title: Test Net
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 4444
    condition: selection
level: high
"""
        self.evaluator.load_rule_from_string(rule_yaml)
        rule = self.evaluator.get_rules()[0]

        self.assertTrue(self.evaluator._rule_matches_event_id(rule, 3))
        self.assertFalse(self.evaluator._rule_matches_event_id(rule, 1))

    def test_registry_set_matches_event_13(self):
        rule_yaml = """
title: Test Reg
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains: '\\Run\\'
    condition: selection
level: high
"""
        self.evaluator.load_rule_from_string(rule_yaml)
        rule = self.evaluator.get_rules()[0]

        self.assertTrue(self.evaluator._rule_matches_event_id(rule, 13))
        self.assertFalse(self.evaluator._rule_matches_event_id(rule, 1))


class TestSigmaFullEvaluation(unittest.TestCase):
    """End-to-end tests: load a rule, evaluate against events, check matches"""

    def setUp(self):
        self.evaluator = SigmaEvaluator()

    def test_encoded_powershell_detection(self):
        rule_yaml = """
title: Encoded PowerShell
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\\powershell.exe'
            - '\\pwsh.exe'
    selection_enc:
        CommandLine|contains:
            - '-enc'
            - '-EncodedCommand'
    condition: selection_img and selection_enc
level: high
"""
        self.evaluator.load_rule_from_string(rule_yaml)

        # Malicious event - should match
        malicious_event = {
            'Image': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            'CommandLine': 'powershell.exe -nop -w hidden -enc SGVsbG8gV29ybGQ=',
            'ProcessId': 1234,
        }
        matches = self.evaluator._evaluate(malicious_event, event_id=1)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule.title, 'Encoded PowerShell')
        self.assertEqual(matches[0].rule.level, 'high')

        # Benign event - should not match
        benign_event = {
            'Image': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            'CommandLine': 'powershell.exe -File script.ps1',
            'ProcessId': 5678,
        }
        matches = self.evaluator._evaluate(benign_event, event_id=1)
        self.assertEqual(len(matches), 0)

    def test_registry_persistence_with_filter(self):
        rule_yaml = """
title: Run Key Persistence
logsource:
    category: registry_set
    product: windows
detection:
    selection:
        TargetObject|contains:
            - '\\CurrentVersion\\Run\\'
            - '\\CurrentVersion\\RunOnce\\'
    filter_legitimate:
        Image|endswith:
            - '\\msiexec.exe'
            - '\\svchost.exe'
    condition: selection and not filter_legitimate
level: high
"""
        self.evaluator.load_rule_from_string(rule_yaml)

        # Suspicious: unknown process modifying Run key
        suspicious_event = {
            'Image': r'C:\Users\test\AppData\Local\Temp\malware.exe',
            'TargetObject': r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run\evil',
            'ProcessId': 999,
        }
        matches = self.evaluator._evaluate(suspicious_event, event_id=13)
        self.assertEqual(len(matches), 1)

        # Legitimate: msiexec modifying Run key (filtered)
        legit_event = {
            'Image': r'C:\Windows\System32\msiexec.exe',
            'TargetObject': r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run\updater',
            'ProcessId': 500,
        }
        matches = self.evaluator._evaluate(legit_event, event_id=13)
        self.assertEqual(len(matches), 0)

    def test_backdoor_port_detection(self):
        rule_yaml = """
title: Backdoor Port Connection
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort:
            - 4444
            - 31337
    condition: selection
level: high
"""
        self.evaluator.load_rule_from_string(rule_yaml)

        # Matching event
        event = {
            'Image': r'C:\Users\test\evil.exe',
            'DestinationPort': '4444',
            'DestinationIp': '10.0.0.1',
        }
        matches = self.evaluator._evaluate(event, event_id=3)
        self.assertEqual(len(matches), 1)

        # Non-matching port
        event2 = {
            'Image': r'C:\Users\test\browser.exe',
            'DestinationPort': '443',
            'DestinationIp': '8.8.8.8',
        }
        matches = self.evaluator._evaluate(event2, event_id=3)
        self.assertEqual(len(matches), 0)

    def test_wrong_event_id_no_match(self):
        """A process_creation rule should not match network events"""
        rule_yaml = """
title: CMD Detection
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
level: medium
"""
        self.evaluator.load_rule_from_string(rule_yaml)

        event = {
            'Image': r'C:\Windows\System32\cmd.exe',
            'DestinationPort': '80',
        }
        # Event ID 3 = network, rule expects process_creation (event ID 1)
        matches = self.evaluator._evaluate(event, event_id=3)
        self.assertEqual(len(matches), 0)

        # Same event with correct event ID should match
        matches = self.evaluator._evaluate(event, event_id=1)
        self.assertEqual(len(matches), 1)

    def test_evaluate_event_dict_psutil(self):
        """Test evaluation of psutil-style event dicts"""
        rule_yaml = """
title: CMD from Office
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
level: medium
"""
        self.evaluator.load_rule_from_string(rule_yaml)

        psutil_event = {
            'event_type': 'Process',
            'operation': 'ProcessCreate',
            'path': r'C:\Windows\System32\cmd.exe',
            'detail': 'Command: cmd.exe /c whoami',
            'pid': 1234,
            'process_name': 'cmd.exe',
        }
        matches = self.evaluator.evaluate_event_dict(psutil_event)
        self.assertEqual(len(matches), 1)

    def test_match_callback(self):
        """Test that match callbacks are triggered"""
        rule_yaml = """
title: Test Callback Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
level: high
"""
        self.evaluator.load_rule_from_string(rule_yaml)

        callback_results = []
        self.evaluator.register_match_callback(lambda m: callback_results.append(m))

        event = {'Image': r'C:\Windows\System32\cmd.exe'}
        self.evaluator._evaluate(event, event_id=1)

        self.assertEqual(len(callback_results), 1)
        self.assertEqual(callback_results[0].rule.title, 'Test Callback Rule')

    def test_sigma_match_to_dict(self):
        """Test SigmaMatch serialization"""
        rule_yaml = """
title: Serialize Test
id: test-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
level: critical
tags:
    - attack.execution
"""
        self.evaluator.load_rule_from_string(rule_yaml)
        event = {'Image': r'C:\Windows\System32\cmd.exe'}
        matches = self.evaluator._evaluate(event, event_id=1)

        self.assertEqual(len(matches), 1)
        d = matches[0].to_dict()
        self.assertEqual(d['rule_title'], 'Serialize Test')
        self.assertEqual(d['rule_id'], 'test-001')
        self.assertEqual(d['rule_level'], 'critical')
        self.assertIn('attack.execution', d['rule_tags'])
        self.assertIn('timestamp', d)


class TestSigmaRuleManagerValidation(unittest.TestCase):
    """Test SigmaRuleManager validation logic"""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.manager = SigmaRuleManager(self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_valid_rule(self):
        rule = """
title: Valid Rule
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
level: high
"""
        valid, err = self.manager.validate_sigma_rule(rule)
        self.assertTrue(valid, f"Unexpected error: {err}")

    def test_missing_title(self):
        rule = """
logsource:
    category: process_creation
detection:
    selection:
        Image: cmd.exe
    condition: selection
"""
        valid, err = self.manager.validate_sigma_rule(rule)
        self.assertFalse(valid)
        self.assertIn('title', err)

    def test_missing_logsource(self):
        rule = """
title: Bad
detection:
    selection:
        Image: cmd.exe
    condition: selection
"""
        valid, err = self.manager.validate_sigma_rule(rule)
        self.assertFalse(valid)
        self.assertIn('logsource', err)

    def test_missing_condition(self):
        rule = """
title: Bad
logsource:
    category: process_creation
detection:
    selection:
        Image: cmd.exe
"""
        valid, err = self.manager.validate_sigma_rule(rule)
        self.assertFalse(valid)
        self.assertIn('condition', err)

    def test_invalid_level(self):
        rule = """
title: Bad
logsource:
    category: process_creation
detection:
    selection:
        Image: cmd.exe
    condition: selection
level: extreme
"""
        valid, err = self.manager.validate_sigma_rule(rule)
        self.assertFalse(valid)
        self.assertIn('level', err.lower())

    def test_invalid_yaml(self):
        rule = "this: is: not: valid: yaml: [[[["
        valid, err = self.manager.validate_sigma_rule(rule)
        self.assertFalse(valid)

    def test_empty_content(self):
        valid, err = self.manager.validate_sigma_rule("")
        self.assertFalse(valid)

    def test_add_and_list_rules(self):
        rule = """
title: Added Rule
logsource:
    category: process_creation
detection:
    selection:
        Image: cmd.exe
    condition: selection
level: high
"""
        success, msg = self.manager.add_rule_from_content("test_rule", rule)
        self.assertTrue(success, f"Failed to add: {msg}")

        rules = self.manager.list_rules()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]['name'], 'test_rule.yml')

    def test_add_duplicate_fails(self):
        rule = """
title: Dup
logsource:
    category: process_creation
detection:
    selection:
        Image: cmd.exe
    condition: selection
"""
        self.manager.add_rule_from_content("dup_rule", rule)
        success, msg = self.manager.add_rule_from_content("dup_rule", rule)
        self.assertFalse(success)
        self.assertIn('already exists', msg)

    def test_get_rule_content(self):
        rule_content = """title: Content Test
logsource:
    category: process_creation
detection:
    selection:
        Image: cmd.exe
    condition: selection
"""
        self.manager.add_rule_from_content("content_test", rule_content)
        success, content = self.manager.get_rule_content("content_test.yml")
        self.assertTrue(success)
        self.assertIn('Content Test', content)

    def test_delete_rule_with_backup(self):
        rule = """
title: Delete Me
logsource:
    category: process_creation
detection:
    selection:
        Image: cmd.exe
    condition: selection
"""
        self.manager.add_rule_from_content("delete_me", rule)
        success, msg = self.manager.delete_rule("delete_me.yml", create_backup=True)
        self.assertTrue(success)
        self.assertIn('backup', msg)

        # Verify file is gone
        rules = self.manager.list_rules()
        self.assertEqual(len(rules), 0)

    def test_update_rule(self):
        original = """
title: Original
logsource:
    category: process_creation
detection:
    selection:
        Image: cmd.exe
    condition: selection
"""
        updated = """
title: Updated
logsource:
    category: process_creation
detection:
    selection:
        Image: powershell.exe
    condition: selection
level: critical
"""
        self.manager.add_rule_from_content("update_test", original)
        success, msg = self.manager.update_rule("update_test.yml", updated)
        self.assertTrue(success)

        _, content = self.manager.get_rule_content("update_test.yml")
        self.assertIn('Updated', content)


class TestSigmaStarterRules(unittest.TestCase):
    """Test that the bundled starter rules all load successfully"""

    def test_all_starter_rules_load(self):
        evaluator = SigmaEvaluator()
        rules_dir = os.path.join(os.path.dirname(__file__), '..', 'sigma_rules')

        if not os.path.exists(rules_dir):
            self.skipTest("sigma_rules directory not found")

        loaded, errors = evaluator.load_rules_from_directory(rules_dir)
        self.assertGreater(loaded, 0, "No rules loaded from sigma_rules/")
        self.assertEqual(len(errors), 0, f"Errors loading rules: {errors}")

    def test_starter_rules_have_required_fields(self):
        """Each starter rule should have title, level, description, and tags"""
        import yaml
        rules_dir = os.path.join(os.path.dirname(__file__), '..', 'sigma_rules')

        if not os.path.exists(rules_dir):
            self.skipTest("sigma_rules directory not found")

        for yml_file in sorted(os.listdir(rules_dir)):
            if not yml_file.endswith('.yml'):
                continue
            with open(os.path.join(rules_dir, yml_file), 'r') as f:
                data = yaml.safe_load(f)

            self.assertIn('title', data, f"{yml_file}: missing title")
            self.assertIn('level', data, f"{yml_file}: missing level")
            self.assertIn('description', data, f"{yml_file}: missing description")
            self.assertIn('tags', data, f"{yml_file}: missing tags")
            self.assertIn('detection', data, f"{yml_file}: missing detection")
            self.assertIn('condition', data['detection'], f"{yml_file}: missing condition")


class TestSigmaStats(unittest.TestCase):
    """Test statistics tracking"""

    def test_stats_tracking(self):
        evaluator = SigmaEvaluator()
        rule_yaml = """
title: Stats Test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\cmd.exe'
    condition: selection
level: high
"""
        evaluator.load_rule_from_string(rule_yaml)

        # Evaluate a matching event
        event = {'Image': r'C:\Windows\System32\cmd.exe'}
        evaluator._evaluate(event, event_id=1)

        # Evaluate a non-matching event
        event2 = {'Image': r'C:\Windows\notepad.exe'}
        evaluator._evaluate(event2, event_id=1)

        stats = evaluator.get_stats()
        self.assertEqual(stats['rules_loaded'], 1)
        self.assertEqual(stats['events_evaluated'], 2)
        self.assertEqual(stats['matches_found'], 1)


if __name__ == '__main__':
    unittest.main()
