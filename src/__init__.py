"""Honeypot Detector — Check token safety before you swap."""

from .honeypot_detector import HoneypotDetector, TokenReport, format_report

__all__ = ["HoneypotDetector", "TokenReport", "format_report"]
__version__ = "1.0.0"
