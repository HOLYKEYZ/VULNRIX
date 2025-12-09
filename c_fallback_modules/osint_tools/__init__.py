# OSINT Tools C Module
# Pure C implementations for secret scanning and search
#
# Build: make
# Usage:
#   ./secret_scanner <path> [output.json]
#   ./search_engine "<query>" [output.json]

import subprocess
import json
import os
from pathlib import Path

__all__ = ['SecretScanner', 'SearchEngine', 'scan_secrets', 'search']

MODULE_DIR = Path(__file__).parent


def _get_exe(name):
    ext = '.exe' if os.name == 'nt' else ''
    return str(MODULE_DIR / f'{name}{ext}')


class SecretScanner:
    """Secret scanner using pure C implementation."""
    
    def __init__(self, timeout: int = 300):
        self.timeout = timeout
        self.exe = _get_exe('secret_scanner')
        
        if not os.path.exists(self.exe):
            raise FileNotFoundError(
                f"C module not built. Run 'make' in {MODULE_DIR}"
            )
    
    def scan(self, path: str, output: str = None) -> dict:
        """
        Scan path for hardcoded secrets.
        
        Args:
            path: File or directory to scan
            output: Optional JSON output file
            
        Returns:
            dict with findings
        """
        args = [self.exe, path]
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
        
        # Parse output
        data = {'path': path, 'findings': [], 'total': 0}
        for line in result.stdout.split('\n'):
            if line.startswith('[!]'):
                data['findings'].append(line.strip())
            elif 'Secrets found:' in line:
                data['total'] = int(line.split(':')[1].strip())
        
        return data


class SearchEngine:
    """Search engine fallback using pure C implementation."""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.exe = _get_exe('search_engine')
        
        if not os.path.exists(self.exe):
            raise FileNotFoundError(
                f"C module not built. Run 'make' in {MODULE_DIR}"
            )
    
    def search(self, query: str, output: str = None) -> dict:
        """
        Search using DuckDuckGo HTML scraping.
        
        Args:
            query: Search query
            output: Optional JSON output file
            
        Returns:
            dict with search results
        """
        args = [self.exe, query]
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
        
        # Parse output
        data = {'query': query, 'results': [], 'count': 0}
        current_result = {}
        
        for line in result.stdout.split('\n'):
            if line.startswith('Found '):
                parts = line.split()
                if len(parts) >= 2:
                    data['count'] = int(parts[1])
            elif line.strip().startswith('URL:'):
                current_result['url'] = line.split(':', 1)[1].strip()
            elif line.strip() and line[0].isdigit() and '. ' in line:
                if current_result:
                    data['results'].append(current_result)
                current_result = {'title': line.split('. ', 1)[1] if '. ' in line else line}
        
        if current_result:
            data['results'].append(current_result)
        
        return data


def scan_secrets(path: str) -> dict:
    """Convenience function for secret scanning."""
    scanner = SecretScanner()
    return scanner.scan(path)


def search(query: str) -> dict:
    """Convenience function for search."""
    engine = SearchEngine()
    return engine.search(query)
