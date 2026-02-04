"""
MAD UI Tabs Package
Individual tab modules for the main application.
"""

from .base_tab import BaseTab
from .new_case_tab import NewCaseTab
from .current_case_tab import CurrentCaseTab
from .analysis_tab import AnalysisTab
from .yara_rules_tab import YaraRulesTab
from .settings_tab import SettingsTab

__all__ = [
    'BaseTab',
    'NewCaseTab',
    'CurrentCaseTab',
    'AnalysisTab',
    'YaraRulesTab',
    'SettingsTab',
]
