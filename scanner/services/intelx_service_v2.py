"""
IntelX Service v2 - With automatic C fallback support.
Extends the original IntelX service with fallback capabilities.
"""

import os
import logging
from typing import Dict, Optional, Any

from scanner.services.fallback.unified_service import UnifiedScannerService
from scanner.services.fallback.api_health_checker import APIHealthChecker

# Import fallback modules
try:
    from c_fallback_modules.breach_checker import BreachFallback
    from c_fallback_modules.dns_scanner import DNSFallback
    HAS_FALLBACK_MODULES = True
except ImportError:
    HAS_FALLBACK_MODULES = False

logger = logging.getLogger('vulnrix.services.intelx')


class IntelXServiceV2(UnifiedScannerService):
    """
    IntelX OSINT service with automatic fallback.
    Falls back to local breach checking when API fails.
    """
    
    api_name = 'intelx'
    fallback_api_names = []
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__()
        self.api_key = api_key or os.getenv('INTELX_API_KEY')
        self.base_url = "https://2.intelx.io/intelligent/search"
        self.headers = {
            "x-key": self.api_key,
            "Content-Type": "application/json"
        } if self.api_key else {}
        
        # Initialize fallback modules
        self._breach_fallback = None
        self._dns_fallback = None
        if HAS_FALLBACK_MODULES:
            self._breach_fallback = BreachFallback()
            self._dns_fallback = DNSFallback()
    
    def _get_c_module(self) -> Optional[Any]:
        """Return fallback module if available."""
        if HAS_FALLBACK_MODULES:
            return {'breach': BreachFallback, 'dns': DNSFallback}
        return None
    
    def search_email(self, email: str, max_results: int = 20) -> Dict:
        """Search for email with automatic fallback."""
        return self.scan(email, scan_type='email_search', max_results=max_results)
    
    def search_username(self, username: str, max_results: int = 20) -> Dict:
        """Search for username with automatic fallback."""
        return self.scan(username, scan_type='username_search', max_results=max_results)
    
    def search_domain(self, domain: str, max_results: int = 20) -> Dict:
        """Search for domain with automatic fallback."""
        return self.scan(domain, scan_type='domain_search', max_results=max_results)
    
    def search_phone(self, phone: str, max_results: int = 20) -> Dict:
        """Search for phone with automatic fallback."""
        # Normalize phone
        normalized = phone.strip().replace('-', '').replace(' ', '').replace('(', '').replace(')', '').replace('+', '')
        return self.scan(normalized, scan_type='phone_search', max_results=max_results)
    
    def _api_scan(self, target: Any, **kwargs) -> Dict:
        """Perform scan using IntelX API."""
        import requests
        
        if not self.api_key:
            raise ValueError("IntelX API key not configured")
        
        max_results = kwargs.get('max_results', 20)
        
        payload = {
            "term": str(target).strip(),
            "maxresults": max_results,
            "media": 0,
            "target": 0,
            "terminate": []
        }
        
        response = requests.post(
            self.base_url,
            headers=self.headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return {
                'results': data.get('selectors', []),
                'total': len(data.get('selectors', [])),
                'raw': data
            }
        elif response.status_code == 401:
            raise ValueError("Invalid IntelX API key")
        elif response.status_code == 429:
            raise ValueError("Rate limit exceeded")
        else:
            raise ValueError(f"API returned status {response.status_code}")
    
    def _c_fallback_scan(self, target: Any, **kwargs) -> Dict:
        """Perform scan using local fallback."""
        scan_type = kwargs.get('scan_type', 'unknown')
        target_str = str(target).strip()
        
        results = {
            'results': [],
            'total': 0,
            'fallback_used': True
        }
        
        # Email search - use breach checker
        if scan_type == 'email_search' and self._breach_fallback:
            breach_result = self._breach_fallback.check_email(target_str)
            if breach_result.get('breached'):
                results['results'] = [{
                    'type': 'breach',
                    'source': 'local_breach_db',
                    'data': breach_result
                }]
                results['total'] = len(breach_result.get('breaches', []))
                results['breach_info'] = breach_result
        
        # Domain search - use DNS fallback
        elif scan_type == 'domain_search' and self._dns_fallback:
            dns_result = self._dns_fallback.get_dns_records(target_str)
            subdomains = self._dns_fallback.enumerate_subdomains(target_str, max_results=20)
            
            results['results'] = [{
                'type': 'dns',
                'source': 'local_dns',
                'dns_records': dns_result,
                'subdomains': subdomains
            }]
            results['total'] = subdomains.get('total', 0)
            results['dns_info'] = dns_result
            results['subdomain_info'] = subdomains
        
        # Username/phone - limited local capability
        else:
            results['note'] = 'Limited local search capability for this type'
        
        return results


# Convenience function to get service instance
def get_intelx_service(api_key: str = None) -> IntelXServiceV2:
    """Get IntelX service with fallback support."""
    return IntelXServiceV2(api_key)
