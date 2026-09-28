"""secret-scanner: pre-commit detection of hardcoded secrets."""

from .detectors import scan_text
from .engine import scan_path

__all__ = ["scan_text", "scan_path"]
__version__ = "0.1.0"
