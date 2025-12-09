# WHOIS Lookup C Module
# Pure C implementation for WHOIS queries
#
# Build: make
# Usage: ./whois_lookup <domain|ip> [output.json] [--raw]

import subprocess
import json
import os
from pathlib import Path

__all__ = ['WhoisLookup', 'lookup']

MODULE_DIR = Path(__file__).parent


def _get_exe():
    ext = '.exe' if os.name == 'nt' else ''
    return str(MODULE_DIR / f'whois_lookup{ext}')


class WhoisLookup:
    """WHOIS lookup using pure C implementation."""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.exe = _get_exe()
        
        if not os.path.exists(self.exe):
            raise FileNotFoundError(
                f"C module not built. Run 'make' in {MODULE_DIR}"
            )
    
    def lookup(self, target: str, output: str = None) -> dict:
        """
        Perform WHOIS lookup.
        
        Args:
            target: Domain or IP address
            output: Optional JSON output file
            
        Returns:
            dict with WHOIS data
        """
        args = [self.exe, target]
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
        
        # Parse stdout for basic info
        data = {'target': target, 'raw': result.stdout}
        
        for line in result.stdout.split('\n'):
            if line.startswith('Registrar:'):
                data['registrar'] = line.split(':', 1)[1].strip()
            elif line.startswith('Created:'):
                data['creation_date'] = line.split(':', 1)[1].strip()
            elif line.startswith('Expires:'):
                data['expiration_date'] = line.split(':', 1)[1].strip()
        
        return data
    
    def lookup_ip(self, ip: str, output: str = None) -> dict:
        """Perform WHOIS lookup for IP address."""
        return self.lookup(ip, output)


def lookup(target: str) -> dict:
    """Convenience function for WHOIS lookup."""
    client = WhoisLookup()
    return client.lookup(target)
