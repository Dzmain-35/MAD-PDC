"""
Analysis Modules Package
Contains YarWatch, Process Monitor, Network Monitor, and Sigma Evaluator modules
"""

from .yarwatch import YarWatch
from .process_monitor import ProcessMonitor
from .network_monitor import NetworkMonitor
from .sigma_evaluator import SigmaEvaluator

__all__ = ['YarWatch', 'ProcessMonitor', 'NetworkMonitor', 'SigmaEvaluator']
__version__ = '1.0.0'