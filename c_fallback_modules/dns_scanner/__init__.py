# DNS Scanner C Module
# Pure C implementation for subdomain enumeration
#
# Build: make
# Usage: ./dns_scan <domain> <wordlist> [threads] [output.json]

import subprocess
import json
import os
from pathlib import Path

__all__ = ['DNSScanner', 'enumerate_subdomains']

MODULE_DIR = Path(__file__).parent


def _get_exe():
    ext = '.exe' if os.name == 'nt' else ''
    return str(MODULE_DIR / f'dns_scan{ext}')


class DNSScanner:
    """DNS subdomain scanner using pure C implementation."""
    
    def __init__(self, threads: int = 10, timeout: int = 300):
        self.threads = threads
        self.timeout = timeout
        self.exe = _get_exe()
        
        if not os.path.exists(self.exe):
            raise FileNotFoundError(
                f"C module not built. Run 'make' in {MODULE_DIR}"
            )
    
    def scan(self, domain: str, wordlist: str, output: str = None) -> dict:
        """
        Enumerate subdomains for a domain.
        
        Args:
            domain: Target domain
            wordlist: Path to wordlist file
            output: Optional JSON output file
            
        Returns:
            dict with subdomains found
        """
        args = [self.exe, domain, wordlist, str(self.threads)]
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
        
        # Parse stdout for results
        subdomains = []
        for line in result.stdout.split('\n'):
            if line.startswith('[+] Found:'):
                parts = line.split(' -> ')
                if len(parts) == 2:
                    subdomain = parts[0].replace('[+] Found: ', '').strip()
                    ip = parts[1].strip()
                    subdomains.append({'subdomain': subdomain, 'ip': ip})
        
        return {
            'domain': domain,
            'subdomains': subdomains,
            'total': len(subdomains)
        }


def enumerate_subdomains(domain: str, wordlist: str, threads: int = 10) -> dict:
    """Convenience function for subdomain enumeration."""
    scanner = DNSScanner(threads=threads)
    return scanner.scan(domain, wordlist)
