"""
IP address scanning module.
"""
import requests
from typing import Dict, Optional


class IPScanner:
    """Scans IP address for geolocation and threat intelligence."""
    
    def __init__(self):
        """Initialize IP scanner."""
        self.ipapi_url = "http://ip-api.com/json/{ip}"
    
    def scan(self, ip: str) -> Dict:
        """
        Scan IP address for information.
        
        Args:
            ip: IP address to scan
        
        Returns:
            Dictionary with IP information
        """
        if not ip:
            return {}
        
        try:
            response = requests.get(self.ipapi_url.format(ip=ip), timeout=10)
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'success':
                return {
                    'ip': data.get('query'),
                    'country': data.get('country'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'as': data.get('as'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'timezone': data.get('timezone')
                }
        except Exception:
            pass
        
        return {}

