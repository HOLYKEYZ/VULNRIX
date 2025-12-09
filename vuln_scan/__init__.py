"""
VulnScan - SQL Injection Scanner
"""

__version__ = "2.2.0"

# Try to import main functions
try:
    from .large_scanner import scan_file, scan_path, get_summary
except ImportError:
    pass

try:
    from .scanner import scan_file, scan_path
except ImportError:
    pass

try:
    from .providers import load_provider, list_providers
except ImportError:
    pass