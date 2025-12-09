# File Analyzer C Module
# Pure C implementations for file hashing and analysis
#
# Build: make
# Usage:
#   ./file_hash <file> [output.json]
#   ./file_analyze <file> [output.json]

import subprocess
import json
import os
from pathlib import Path

__all__ = ['FileHasher', 'FileAnalyzer', 'hash_file', 'analyze_file']

MODULE_DIR = Path(__file__).parent


def _get_exe(name):
    ext = '.exe' if os.name == 'nt' else ''
    return str(MODULE_DIR / f'{name}{ext}')


class FileHasher:
    """File hash computer using pure C implementation."""
    
    def __init__(self):
        self.exe = _get_exe('file_hash')
        
        if not os.path.exists(self.exe):
            raise FileNotFoundError(
                f"C module not built. Run 'make' in {MODULE_DIR}"
            )
    
    def hash(self, filepath: str, output: str = None) -> dict:
        """
        Compute file hashes (MD5, SHA256).
        
        Args:
            filepath: Path to file
            output: Optional JSON output file
            
        Returns:
            dict with hashes
        """
        args = [self.exe, filepath]
        if output:
            args.append(output)
        
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        
        if output and os.path.exists(output):
            with open(output) as f:
                return json.load(f)
        
        # Parse output
        data = {'filename': filepath}
        for line in result.stdout.split('\n'):
            if line.startswith('MD5:'):
                data['md5'] = line.split(':', 1)[1].strip()
            elif line.startswith('SHA256:'):
                data['sha256'] = line.split(':', 1)[1].strip()
            elif line.startswith('Size:'):
                size_str = line.split(':', 1)[1].strip().split()[0]
                data['file_size'] = int(size_str)
        
        return data


class FileAnalyzer:
    """File analyzer using pure C implementation."""
    
    def __init__(self):
        self.exe = _get_exe('file_analyze')
        
        if not os.path.exists(self.exe):
            raise FileNotFoundError(
                f"C module not built. Run 'make' in {MODULE_DIR}"
            )
    
    def analyze(self, filepath: str, output: str = None) -> dict:
        """
        Analyze file for suspicious patterns.
        
        Args:
            filepath: Path to file
            output: Optional JSON output file
            
        Returns:
            dict with analysis results
        """
        args = [self.exe, filepath]
        if output:
            args.append(output)
        
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        
        if output and os.path.exists(output):
            with open(output) as f:
                return json.load(f)
        
        # Parse output
        data = {'filename': filepath, 'findings': []}
        for line in result.stdout.split('\n'):
            if line.startswith('Risk Score:'):
                data['risk_score'] = int(line.split(':')[1].split('/')[0].strip())
            elif line.startswith('Risk Level:'):
                data['risk_level'] = line.split(':', 1)[1].strip()
            elif line.startswith('Type:'):
                data['file_type'] = line.split(':', 1)[1].strip()
            elif line.startswith('[!]') or line.startswith('[*]'):
                data['findings'].append(line.strip())
        
        return data


def hash_file(filepath: str) -> dict:
    """Convenience function for file hashing."""
    hasher = FileHasher()
    return hasher.hash(filepath)


def analyze_file(filepath: str) -> dict:
    """Convenience function for file analysis."""
    analyzer = FileAnalyzer()
    return analyzer.analyze(filepath)
