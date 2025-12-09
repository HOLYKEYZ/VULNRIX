# Network Scanner C Module
# Pure C implementations for port scanning and banner grabbing
#
# Build: make
# Usage: 
#   ./port_scan <target> [ports] [threads] [timeout] [output.json]
#   ./banner_grab <host> <port1,port2,...> [output.json]

import subprocess
import json
import os
from pathlib import Path

__all__ = ['PortScanner', 'BannerGrabber', 'scan_ports', 'grab_banners']

MODULE_DIR = Path(__file__).parent


def _get_exe(name):
    ext = '.exe' if os.name == 'nt' else ''
    return str(MODULE_DIR / f'{name}{ext}')


class PortScanner:
    """TCP port scanner using pure C implementation."""
    
    def __init__(self, threads: int = 50, timeout_ms: int = 1000):
        self.threads = threads
        self.timeout_ms = timeout_ms
        self.exe = _get_exe('port_scan')
        
        if not os.path.exists(self.exe):
            raise FileNotFoundError(
                f"C module not built. Run 'make' in {MODULE_DIR}"
            )
    
    def scan(self, target: str, ports: str = 'top100', output: str = None) -> dict:
        """
        Scan target for open ports.
        
        Args:
            target: IP or hostname
            ports: Port spec (top100, top1000, all, 1-1000, 80,443,8080)
            output: Optional JSON output file
            
        Returns:
            dict with open ports
        """
        args = [self.exe, target, ports, str(self.threads), str(self.timeout_ms)]
        if output:
            args.append(output)
        
        result = subprocess.run(args, capture_output=True, text=True, timeout=600)
        
        if output and os.path.exists(output):
            with open(output) as f:
                return json.load(f)
        
        # Parse stdout
        ports_found = []
        for line in result.stdout.split('\n'):
            if '/tcp open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = int(parts[1].split('/')[0].replace('[+]', ''))
                    service = parts[3] if len(parts) > 3 else 'unknown'
                    ports_found.append({'port': port, 'service': service})
        
        return {
            'target': target,
            'ports': ports_found,
            'total_open': len(ports_found)
        }


class BannerGrabber:
    """Service banner grabber using pure C implementation."""
    
    def __init__(self):
        self.exe = _get_exe('banner_grab')
        
        if not os.path.exists(self.exe):
            raise FileNotFoundError(
                f"C module not built. Run 'make' in {MODULE_DIR}"
            )
    
    def grab(self, host: str, ports: list, output: str = None) -> dict:
        """
        Grab banners from open ports.
        
        Args:
            host: Target host
            ports: List of ports
            output: Optional JSON output file
            
        Returns:
            dict with banners
        """
        ports_str = ','.join(str(p) for p in ports)
        args = [self.exe, host, ports_str]
        if output:
            args.append(output)
        
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        
        if output and os.path.exists(output):
            with open(output) as f:
                return json.load(f)
        
        return {'stdout': result.stdout, 'stderr': result.stderr}


def scan_ports(target: str, ports: str = 'top100', threads: int = 50) -> dict:
    """Convenience function for port scanning."""
    scanner = PortScanner(threads=threads)
    return scanner.scan(target, ports)


def grab_banners(host: str, ports: list) -> dict:
    """Convenience function for banner grabbing."""
    grabber = BannerGrabber()
    return grabber.grab(host, ports)
