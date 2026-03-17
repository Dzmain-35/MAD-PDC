"""Pytest configuration and shared fixtures for MAD-PDC tests."""

import os
import sys

# Ensure project root is on the path for imports
PROJECT_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
