"""
MAD UI Package
Modular user interface components for the Malware Analysis Dashboard.

This package provides a modular architecture for the MAD application:
- theme.py: Color scheme and styling constants
- tabs/: Individual tab modules (new_case, current_case, analysis, yara_rules, settings)
- dialogs/: Dialog windows (progress, yara)

Usage:
    The original MAD.py can continue to work as the main entry point.
    Gradually migrate components to use these modules for better maintainability.
"""

from .theme import Theme, Colors

# Note: ForensicAnalysisGUI import is commented out to avoid circular imports
# when MAD.py is still the main entry point. Uncomment when fully migrated.
# from .app import ForensicAnalysisGUI

__all__ = ['Theme', 'Colors']
