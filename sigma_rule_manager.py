"""
Sigma Rule Manager - Handles loading, validation, adding, deleting, and syncing Sigma rules

Mirrors the design of yara_rule_manager.py but for Sigma YAML detection rules.
"""

import os
import shutil
from pathlib import Path
from datetime import datetime
from datetime_utils import get_current_datetime
from typing import Tuple, List, Dict, Any, Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


class SigmaRuleManager:
    """Manager for Sigma rules with validation, file operations, and network sync"""

    REQUIRED_FIELDS = ['title', 'logsource', 'detection']

    def __init__(self, sigma_rules_path: str, settings_manager=None):
        """
        Initialize the Sigma Rule Manager

        Args:
            sigma_rules_path: Path to the directory containing Sigma rules
            settings_manager: Optional SettingsManager instance for network sync
        """
        self.sigma_rules_path = Path(sigma_rules_path)
        self.settings_manager = settings_manager

    def validate_sigma_rule(self, rule_content: str) -> Tuple[bool, str]:
        """
        Validate Sigma rule YAML syntax and structure.

        Args:
            rule_content: String containing Sigma rule YAML content

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not YAML_AVAILABLE:
            return False, "PyYAML is not installed. Install with: pip install pyyaml"

        if not rule_content or not rule_content.strip():
            return False, "Rule content is empty"

        try:
            rule_data = yaml.safe_load(rule_content)
        except yaml.YAMLError as e:
            return False, f"YAML Syntax Error: {e}"

        if not isinstance(rule_data, dict):
            return False, "Rule content must be a YAML mapping (dictionary)"

        # Check required fields
        for field in self.REQUIRED_FIELDS:
            if field not in rule_data:
                return False, f"Missing required field: '{field}'"

        # Validate logsource
        logsource = rule_data.get('logsource', {})
        if not isinstance(logsource, dict):
            return False, "logsource must be a mapping"

        # Validate detection
        detection = rule_data.get('detection', {})
        if not isinstance(detection, dict):
            return False, "detection must be a mapping"
        if 'condition' not in detection:
            return False, "detection section must include a 'condition' field"

        # Validate level if present
        level = rule_data.get('level', '')
        if level and level not in ('informational', 'low', 'medium', 'high', 'critical'):
            return False, f"Invalid level: '{level}'. Must be one of: informational, low, medium, high, critical"

        # Validate status if present
        status = rule_data.get('status', '')
        if status and status not in ('stable', 'test', 'experimental', 'deprecated', 'unsupported'):
            return False, f"Invalid status: '{status}'. Must be one of: stable, test, experimental, deprecated, unsupported"

        return True, ""

    def validate_sigma_file(self, file_path: str) -> Tuple[bool, str]:
        """
        Validate a Sigma rule file.

        Args:
            file_path: Path to the Sigma rule file

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not os.path.exists(file_path):
            return False, f"File not found: {file_path}"

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule_content = f.read()
            return self.validate_sigma_rule(rule_content)
        except Exception as e:
            return False, f"Error reading file: {e}"

    def add_rule_from_content(self, rule_name: str, rule_content: str) -> Tuple[bool, str]:
        """
        Add a new Sigma rule from YAML content string.

        Args:
            rule_name: Name for the rule file (without extension)
            rule_content: Sigma rule YAML content

        Returns:
            Tuple of (success, message)
        """
        is_valid, error_msg = self.validate_sigma_rule(rule_content)
        if not is_valid:
            return False, f"Rule validation failed: {error_msg}"

        if not rule_name.endswith('.yml') and not rule_name.endswith('.yaml'):
            rule_name += '.yml'

        rule_path = self.sigma_rules_path / rule_name

        if rule_path.exists():
            return False, f"Rule file '{rule_name}' already exists"

        try:
            self.sigma_rules_path.mkdir(parents=True, exist_ok=True)

            with open(rule_path, 'w', encoding='utf-8') as f:
                f.write(rule_content)

            # Sync to network if enabled
            net_ok, net_msg = self._sync_rule_to_network(rule_name, rule_content)

            if net_ok and net_msg:
                return True, f"Successfully added rule '{rule_name}'. {net_msg}"
            elif not net_ok:
                return True, f"Successfully added rule '{rule_name}' (Warning: {net_msg})"

            return True, f"Successfully added rule '{rule_name}'"
        except Exception as e:
            return False, f"Error writing rule file: {e}"

    def add_rule_from_file(self, source_file_path: str) -> Tuple[bool, str]:
        """
        Add a Sigma rule from an external file.

        Args:
            source_file_path: Path to the source Sigma rule file

        Returns:
            Tuple of (success, message)
        """
        is_valid, error_msg = self.validate_sigma_file(source_file_path)
        if not is_valid:
            return False, f"Rule validation failed: {error_msg}"

        try:
            source_path = Path(source_file_path)
            dest_path = self.sigma_rules_path / source_path.name

            if dest_path.exists():
                return False, f"Rule file '{source_path.name}' already exists"

            self.sigma_rules_path.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file_path, dest_path)

            return True, f"Successfully added rule '{source_path.name}'"
        except Exception as e:
            return False, f"Error copying rule file: {e}"

    def delete_rule(self, rule_name: str, create_backup: bool = True) -> Tuple[bool, str]:
        """
        Delete a Sigma rule file.

        Args:
            rule_name: Name of the rule file to delete
            create_backup: If True, creates a backup before deletion

        Returns:
            Tuple of (success, message)
        """
        rule_path = self.sigma_rules_path / rule_name

        if not rule_path.exists():
            return False, f"Rule file '{rule_name}' not found"

        try:
            if create_backup:
                backup_dir = self.sigma_rules_path / "_backups"
                backup_dir.mkdir(exist_ok=True)

                timestamp = get_current_datetime().strftime("%Y%m%d_%H%M%S")
                backup_name = f"{rule_path.stem}_{timestamp}{rule_path.suffix}"
                backup_path = backup_dir / backup_name
                shutil.copy2(rule_path, backup_path)

            rule_path.unlink()

            if create_backup:
                return True, f"Rule '{rule_name}' deleted (backup created)"
            return True, f"Rule '{rule_name}' deleted"
        except Exception as e:
            return False, f"Error deleting rule: {e}"

    def update_rule(self, rule_name: str, new_content: str, create_backup: bool = True) -> Tuple[bool, str]:
        """
        Update an existing Sigma rule.

        Args:
            rule_name: Name of the rule file to update
            new_content: New YAML content
            create_backup: If True, creates a backup before updating

        Returns:
            Tuple of (success, message)
        """
        rule_path = self.sigma_rules_path / rule_name

        if not rule_path.exists():
            return False, f"Rule file '{rule_name}' not found"

        is_valid, error_msg = self.validate_sigma_rule(new_content)
        if not is_valid:
            return False, f"Rule validation failed: {error_msg}"

        try:
            if create_backup:
                backup_dir = self.sigma_rules_path / "_backups"
                backup_dir.mkdir(exist_ok=True)

                timestamp = get_current_datetime().strftime("%Y%m%d_%H%M%S")
                backup_name = f"{rule_path.stem}_{timestamp}{rule_path.suffix}"
                backup_path = backup_dir / backup_name
                shutil.copy2(rule_path, backup_path)

            with open(rule_path, 'w', encoding='utf-8') as f:
                f.write(new_content)

            net_ok, net_msg = self._sync_rule_to_network(rule_name, new_content)

            backup_msg = " (backup created)" if create_backup else ""
            if net_ok and net_msg:
                return True, f"Rule '{rule_name}' updated{backup_msg}. {net_msg}"
            elif not net_ok:
                return True, f"Rule '{rule_name}' updated{backup_msg} (Warning: {net_msg})"

            return True, f"Rule '{rule_name}' updated{backup_msg}"
        except Exception as e:
            return False, f"Error updating rule: {e}"

    def list_rules(self) -> List[Dict[str, Any]]:
        """
        List all Sigma rules in the directory.

        Returns:
            List of rule info dictionaries
        """
        if not self.sigma_rules_path.exists():
            return []

        rules = []
        try:
            for ext in ("*.yml", "*.yaml"):
                for rule_file in sorted(self.sigma_rules_path.glob(ext)):
                    info = {
                        "name": rule_file.name,
                        "path": str(rule_file),
                        "size": rule_file.stat().st_size,
                        "modified": datetime.fromtimestamp(rule_file.stat().st_mtime),
                    }

                    # Try to extract title and level from YAML
                    if YAML_AVAILABLE:
                        try:
                            with open(rule_file, 'r', encoding='utf-8') as f:
                                data = yaml.safe_load(f)
                            if isinstance(data, dict):
                                info['title'] = data.get('title', '')
                                info['level'] = data.get('level', '')
                                info['status'] = data.get('status', '')
                                info['description'] = data.get('description', '')
                        except Exception:
                            pass

                    rules.append(info)
        except Exception as e:
            print(f"Error listing sigma rules: {e}")

        return rules

    def get_rule_content(self, rule_name: str) -> Tuple[bool, str]:
        """
        Get the content of a specific Sigma rule.

        Args:
            rule_name: Name of the rule file

        Returns:
            Tuple of (success, content_or_error)
        """
        rule_path = self.sigma_rules_path / rule_name

        if not rule_path.exists():
            return False, f"Rule file '{rule_name}' not found"

        try:
            with open(rule_path, 'r', encoding='utf-8') as f:
                content = f.read()
            return True, content
        except Exception as e:
            return False, f"Error reading rule: {e}"

    def _sync_rule_to_network(self, rule_name: str, rule_content: str) -> Tuple[bool, str]:
        """Sync a Sigma rule to the network folder."""
        if not self.settings_manager:
            return True, ""

        if not self.settings_manager.get("sigma.enable_network_sigma_sync", False):
            return True, ""

        network_path = self.settings_manager.get("sigma.network_sigma_path", "")
        if not network_path:
            return True, ""

        try:
            os.makedirs(network_path, exist_ok=True)

            if not rule_name.endswith('.yml') and not rule_name.endswith('.yaml'):
                rule_name += '.yml'

            network_rule_path = os.path.join(network_path, rule_name)
            with open(network_rule_path, 'w', encoding='utf-8') as f:
                f.write(rule_content)

            return True, f"Synced to network: {network_rule_path}"
        except Exception as e:
            return False, f"Network sync failed: {e}"
