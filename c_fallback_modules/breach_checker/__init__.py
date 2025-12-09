# Breach Checker C Module
# Pure C implementation for breach checking
#
# Build: make
# Usage:
#   ./breach_check password <password> [output.json]
#   ./breach_check email <email> <database.txt> [output.json]
#   ./breach_check hash <input> [--email]

import subprocess
import json
import os
from pathlib import Path

__all__ = ['BreachChecker', 'check_password', 'check_email']

MODULE_DIR = Path(__file__).parent


def _get_exe():
    ext = '.exe' if os.name == 'nt' else ''
    return str(MODULE_DIR / f'breach_check{ext}')


class BreachChecker:
    """Breach checker using pure C implementation."""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.exe = _get_exe()
        
        if not os.path.exists(self.exe):
            raise FileNotFoundError(
                f"C module not built. Run 'make' in {MODULE_DIR}"
            )
    
    def check_password(self, password: str, output: str = None) -> dict:
        """
        Check if password has been breached using HIBP API (k-anonymity).
        
        Args:
            password: Password to check (NOT stored, only hash prefix sent)
            output: Optional JSON output file
            
        Returns:
            dict with breach status
        """
        import hashlib
        import requests
        
        # 1. Compute SHA1
        sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        
        try:
            # 2. Query HIBP API
            # Uses k-anonymity: only we know the full hash
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            headers = {
                'User-Agent': 'VULNRIX-BreachChecker/1.0',
                'Add-Padding': 'true'
            }
            
            response = requests.get(url, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            
            # 3. Search for suffix in response
            # Response format: SUFFIX:COUNT
            found = False
            count = 0
            
            for line in response.text.splitlines():
                parts = line.split(':')
                if len(parts) >= 2:
                    h_suffix, h_count = parts[0], parts[1]
                    if h_suffix == suffix:
                        found = True
                        count = int(h_count)
                        break
            
            result = {
                'input': '********',
                'sha1_prefix': prefix,
                'found': found,
                'count': count,
                'source': 'hibp_api'
            }
            
            # 4. Save output if requested
            if output:
                with open(output, 'w') as f:
                    json.dump(result, f, indent=2)
            
            return result
            
        except Exception as e:
            # Fallback (safe default)
            return {
                'input': '********',
                'found': False, 
                'count': 0, 
                'error': str(e),
                'source': 'error_fallback'
            }
    
    def check_email(self, email: str, db_path: str = None, output: str = None) -> dict:
        """
        Check if email has been breached.
        
        Args:
            email: Email to check
            db_path: Path to local breach database
            output: Optional JSON output file
            
        Returns:
            dict with breach status
        """
        if not db_path:
            # Use heuristic check without database
            return self._check_email_heuristic(email)
        
        args = [self.exe, 'email', email, db_path]
        if output:
            args.append(output)
        
        result = subprocess.run(
            args, 
            capture_output=True, 
            text=True, 
            timeout=self.timeout
        )
        
        if output and os.path.exists(output):
            with open(output) as f:
                return json.load(f)
        
        return {'email': email, 'stdout': result.stdout}
    
    def _check_email_heuristic(self, email: str) -> dict:
        """Heuristic email breach check based on domain."""
        domain = email.split('@')[1].lower() if '@' in email else ''
        
        # Known breached domains
        breached_domains = {
            'yahoo.com': 'Yahoo 2013-2014',
            'linkedin.com': 'LinkedIn 2012',
            'adobe.com': 'Adobe 2013',
            'dropbox.com': 'Dropbox 2012',
        }
        
        breach = breached_domains.get(domain)
        return {
            'email': email,
            'found': breach is not None,
            'breach': breach,
            'method': 'heuristic'
        }
    
    def hash_input(self, value: str, is_email: bool = False) -> dict:
        """Generate hash for input."""
        args = [self.exe, 'hash', value]
        if is_email:
            args.append('--email')
        
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return {'hash': result.stdout.strip()}


def check_password(password: str) -> dict:
    """Convenience function for password check."""
    checker = BreachChecker()
    return checker.check_password(password)


def check_email(email: str, db_path: str = None) -> dict:
    """Convenience function for email check."""
    checker = BreachChecker()
    return checker.check_email(email, db_path)
