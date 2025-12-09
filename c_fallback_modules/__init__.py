# C Fallback Modules for VULNRIX
# Pure C implementations for high-performance local scanning when APIs fail
#
# Build Instructions:
#   cd c_fallback_modules
#   make all
#
# Modules:
#   - dns_scanner: Subdomain enumeration (dns_scan)
#   - network_scanner: Port scanning & banner grabbing (port_scan, banner_grab)
#   - whois_lookup: WHOIS queries (whois_lookup)
#   - file_analyzer: File hashing & analysis (file_hash, file_analyze)
#   - breach_checker: Password/email breach checking (breach_check)
#   - osint_tools: Secret scanning & search (secret_scanner, search_engine)
#
# Each module compiles to standalone executables that can be called via subprocess

__version__ = '2.0.0'

import subprocess
import json
import os
from pathlib import Path

# Get the directory containing C executables
C_MODULES_DIR = Path(__file__).parent


def _get_executable(module: str, name: str) -> str:
    """Get path to C executable."""
    ext = '.exe' if os.name == 'nt' else ''
    path = C_MODULES_DIR / module / f"{name}{ext}"
    return str(path) if path.exists() else None


def _run_c_module(module: str, name: str, args: list, parse_json: bool = False):
    """Run a C module and return output."""
    exe = _get_executable(module, name)
    if not exe:
        raise FileNotFoundError(f"C module not found: {module}/{name}. Run 'make' to build.")
    
    cmd = [exe] + args
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    
    if parse_json and result.returncode == 0:
        # Try to parse JSON output file if specified
        for arg in args:
            if arg.endswith('.json') and os.path.exists(arg):
                with open(arg) as f:
                    return json.load(f)
    
    return {
        'stdout': result.stdout,
        'stderr': result.stderr,
        'returncode': result.returncode
    }


# Convenience functions for each module
def dns_scan(domain: str, wordlist: str, threads: int = 10, output: str = None):
    """Run DNS subdomain scanner."""
    args = [domain, wordlist, str(threads)]
    if output:
        args.append(output)
    return _run_c_module('dns_scanner', 'dns_scan', args, parse_json=bool(output))


def port_scan(target: str, ports: str = 'top100', threads: int = 50, output: str = None):
    """Run port scanner."""
    args = [target, ports, str(threads)]
    if output:
        args.append(output)
    return _run_c_module('network_scanner', 'port_scan', args, parse_json=bool(output))


def whois_lookup(domain: str, output: str = None):
    """Run WHOIS lookup."""
    args = [domain]
    if output:
        args.append(output)
    return _run_c_module('whois_lookup', 'whois_lookup', args, parse_json=bool(output))


def file_hash(filepath: str, output: str = None):
    """Compute file hashes."""
    args = [filepath]
    if output:
        args.append(output)
    return _run_c_module('file_analyzer', 'file_hash', args, parse_json=bool(output))


def file_analyze(filepath: str, output: str = None):
    """Analyze file for threats."""
    args = [filepath]
    if output:
        args.append(output)
    return _run_c_module('file_analyzer', 'file_analyze', args, parse_json=bool(output))


def breach_check(mode: str, value: str, db_path: str = None, output: str = None):
    """Check for breaches."""
    args = [mode, value]
    if db_path:
        args.append(db_path)
    if output:
        args.append(output)
    return _run_c_module('breach_checker', 'breach_check', args, parse_json=bool(output))


def secret_scan(path: str, output: str = None):
    """Scan for secrets."""
    args = [path]
    if output:
        args.append(output)
    return _run_c_module('osint_tools', 'secret_scanner', args, parse_json=bool(output))


def search(query: str, output: str = None):
    """Search using fallback engine."""
    args = [query]
    if output:
        args.append(output)
    return _run_c_module('osint_tools', 'search_engine', args, parse_json=bool(output))


def hibp_password_check(password: str) -> dict:
    """
    Check password against Have I Been Pwned using k-anonymity.
    Uses Python requests (HTTPS supported) since C module cannot do HTTPS.
    
    Returns:
        dict with 'found' (bool) and 'count' (int) of exposures
    """
    import hashlib
    import requests
    
    # Hash the password with SHA-1
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]
    
    try:
        # Query HIBP API with just the prefix (k-anonymity)
        response = requests.get(
            f'https://api.pwnedpasswords.com/range/{prefix}',
            headers={'User-Agent': 'VULNRIX-BreachChecker/1.0'},
            timeout=10
        )
        response.raise_for_status()
        
        # Check if our suffix is in the response
        for line in response.text.splitlines():
            hash_suffix, count = line.split(':')
            if hash_suffix.upper() == suffix:
                return {
                    'found': True,
                    'count': int(count),
                    'sha1_prefix': prefix,
                    'source': 'hibp_api'
                }
        
        return {
            'found': False,
            'count': 0,
            'sha1_prefix': prefix,
            'source': 'hibp_api'
        }
    except Exception as e:
        return {
            'found': None,  # Unknown
            'count': 0,
            'error': str(e),
            'source': 'hibp_api_error'
        }


def hibp_email_check(email: str, api_key: str = None) -> dict:
    """
    Check email against Have I Been Pwned breaches.
    Requires HIBP API key for breach lookups.
    
    Returns:
        dict with breach information
    """
    import requests
    import os
    
    api_key = api_key or os.getenv('HIBP_API_KEY')
    if not api_key:
        return {
            'breaches': [],
            'total_breaches': 0,
            'error': 'HIBP API key not configured',
            'source': 'hibp_api'
        }
    
    try:
        response = requests.get(
            f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}',
            headers={
                'User-Agent': 'VULNRIX-BreachChecker/1.0',
                'hibp-api-key': api_key
            },
            params={'truncateResponse': 'false'},
            timeout=10
        )
        
        if response.status_code == 404:
            return {
                'breaches': [],
                'total_breaches': 0,
                'source': 'hibp_api'
            }
        
        response.raise_for_status()
        breaches = response.json()
        
        return {
            'breaches': breaches,
            'total_breaches': len(breaches),
            'source': 'hibp_api'
        }
    except Exception as e:
        return {
            'breaches': [],
            'total_breaches': 0,
            'error': str(e),
            'source': 'hibp_api_error'
        }

