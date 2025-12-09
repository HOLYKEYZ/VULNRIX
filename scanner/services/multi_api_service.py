"""
Multi-API Service - Tries all available APIs before using C fallback.
Implements intelligent API rotation and automatic fallback logic.
"""

import os
import logging
import time
from typing import Dict, List, Any
from datetime import datetime

from scanner.services.fallback.unified_service import UnifiedScannerService
from scanner.services.fallback.api_health_checker import APIHealthChecker

logger = logging.getLogger('vulnrix.services.multi_api')


class MultiAPIService(UnifiedScannerService):
    """
    Service that tries multiple APIs before falling back to C implementation.
    Automatically rotates through available API keys.
    """
    
    def __init__(self, primary_api: str, fallback_apis: List[str] = None):
        super().__init__()
        self.primary_api = primary_api
        self.fallback_apis = fallback_apis or []
        self.api_name = primary_api
    
    def scan(self, target: Any, scan_type: str = None, **kwargs) -> Dict:
        """
        Try all APIs before using C fallback.
        """
        scan_type = scan_type or self.primary_api
        
        # 1. Try primary API with all available keys
        result = self._try_api_with_rotation(self.primary_api, target, scan_type, **kwargs)
        if result.get('success'):
            return result
        
        # 2. Try fallback APIs
        for fallback_api in self.fallback_apis:
            result = self._try_api_with_rotation(fallback_api, target, scan_type, **kwargs)
            if result.get('success'):
                return result
        
        # 3. Use C fallback as last resort
        if self._c_module_loaded:
            return self._try_c_fallback_scan(target, scan_type, **kwargs)
        
        # 4. All methods failed
        return self._format_result(
            data=None,
            source='none',
            success=False,
            error='All APIs and C fallback failed'
        )
    
    def _try_api_with_rotation(self, api_name: str, target: Any, scan_type: str, **kwargs) -> Dict:
        """Try an API with key rotation."""
        api_keys = self.health_checker._get_all_api_keys(api_name)
        
        if not api_keys:
            logger.warning(f"No API keys found for {api_name}")
            return self._format_result(None, source=f'api:{api_name}', success=False, 
                                       error=f'No API keys configured for {api_name}')
        
        for key_index, api_key in enumerate(api_keys):
            start_time = time.time()
            try:
                # Try the API with this key
                result = self._api_scan_with_key(target, api_name, api_key, **kwargs)
                duration_ms = (time.time() - start_time) * 1000
                
                # Record success
                self.metrics.record(
                    method='api',
                    scan_type=scan_type,
                    success=True,
                    duration_ms=duration_ms,
                    api_name=f"{api_name}_key_{key_index + 1}"
                )
                
                return self._format_result(result, source=f'api:{api_name}', success=True)
                
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                logger.warning(f"API {api_name} key {key_index + 1} failed: {e}")
                
                # Record failure
                self.metrics.record(
                    method='api',
                    scan_type=scan_type,
                    success=False,
                    duration_ms=duration_ms,
                    api_name=f"{api_name}_key_{key_index + 1}",
                    error=str(e)
                )
                continue
        
        # All keys for this API failed
        return self._format_result(None, source=f'api:{api_name}', success=False, 
                                   error=f'All {len(api_keys)} keys failed for {api_name}')
    
    def _api_scan_with_key(self, target: Any, api_name: str, api_key: str, **kwargs) -> Any:
        """Override in subclass to implement API-specific scanning."""
        raise NotImplementedError(f"API scan not implemented for {api_name}")
    
    def _api_scan(self, target: Any, **kwargs) -> Any:
        """Default implementation - uses primary API."""
        api_key = self.health_checker._get_api_key(self.primary_api)
        if not api_key:
            raise ValueError(f"No API key for {self.primary_api}")
        return self._api_scan_with_key(target, self.primary_api, api_key, **kwargs)
    
    def _c_fallback_scan(self, target: Any, **kwargs) -> Any:
        """Default C fallback - override in subclass."""
        return {'message': 'C fallback not implemented for this service'}


class EmailScanService(MultiAPIService):
    """Email scanning with multiple API fallbacks."""
    
    def __init__(self):
        super().__init__(
            primary_api='leakinsight',
            fallback_apis=['leak_lookup', 'intelx']
        )
    
    def _api_scan_with_key(self, email: str, api_name: str, api_key: str, **kwargs) -> Dict:
        """Scan email with specific API."""
        import requests
        
        if api_name == 'leakinsight':
            # LeakInsight via RapidAPI
            response = requests.get(
                f'https://leakinsight.p.rapidapi.com/email/{email}',
                headers={
                    'X-RapidAPI-Key': api_key,
                    'X-RapidAPI-Host': 'leakinsight.p.rapidapi.com'
                },
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return {'email': email, 'breached': data.get('found', False), 'data': data}
            else:
                raise ValueError(f"LeakInsight API error: {response.status_code}")
                
        elif api_name == 'leak_lookup':
            response = requests.post(
                'https://leak-lookup.com/api/search',
                data={'key': api_key, 'type': 'email_address', 'query': email},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return {'email': email, 'breached': data.get('error') != 'true', 'data': data}
            else:
                raise ValueError(f"Leak-Lookup API error: {response.status_code}")
        
        raise ValueError(f"Unknown API: {api_name}")
    
    def _get_c_module(self):
        """Load breach checker C module."""
        try:
            from c_fallback_modules.breach_checker import BreachChecker
            return BreachChecker()
        except (ImportError, FileNotFoundError):
            return None
    
    def _c_fallback_scan(self, email: str, **kwargs) -> Dict:
        """Use breach checker fallback."""
        if self._c_module:
            return self._c_module.check_email(email)
        # Heuristic fallback if C module not available
        domain = email.split('@')[1].lower() if '@' in email else ''
        breached_domains = {'yahoo.com', 'linkedin.com', 'adobe.com', 'dropbox.com'}
        return {
            'email': email, 
            'breached': domain in breached_domains, 
            'message': 'Heuristic check only', 
            'source': 'fallback'
        }


class PhoneScanService(MultiAPIService):
    """Phone number scanning with Veriphone and NumLookup only."""
    
    def __init__(self):
        super().__init__(
            primary_api='veriphone',
            fallback_apis=['numlookup']
        )
    
    def _api_scan_with_key(self, phone: str, api_name: str, api_key: str, **kwargs) -> Dict:
        """Scan phone with specific API."""
        import requests
        
        if api_name == 'veriphone':
            response = requests.get(
                f'https://api.veriphone.io/v2/verify?phone={phone}&key={api_key}',
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'phone': phone,
                    'valid': data.get('phone_valid', False),
                    'carrier': data.get('carrier'),
                    'country': data.get('country'),
                    'type': data.get('phone_type')
                }
            else:
                raise ValueError(f"Veriphone API error: {response.status_code}")
                
        elif api_name == 'numlookup':
            response = requests.get(
                f'https://api.numlookupapi.com/v1/validate/{phone}',
                headers={'apikey': api_key},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return {
                    'phone': phone,
                    'valid': data.get('valid', False),
                    'carrier': data.get('carrier'),
                    'country': data.get('country_name'),
                    'type': data.get('line_type')
                }
            else:
                raise ValueError(f"NumLookup API error: {response.status_code}")
        
        raise ValueError(f"Unknown API: {api_name}")
    
    def _c_fallback_scan(self, phone: str, **kwargs) -> Dict:
        """Local phone validation fallback."""
        import re
        cleaned = re.sub(r'[^\d+]', '', phone)
        is_valid = 10 <= len(cleaned) <= 15
        return {
            'phone': phone,
            'valid': is_valid,
            'method': 'local_validation',
            'note': 'Basic validation only - API unavailable'
        }


class DomainScanService(MultiAPIService):
    """Domain scanning with multiple API fallbacks."""
    
    def __init__(self):
        super().__init__(
            primary_api='whoisfreaks',
            fallback_apis=['securitytrails', 'shodan']
        )
    
    def _api_scan_with_key(self, domain: str, api_name: str, api_key: str, **kwargs) -> Dict:
        """Scan domain with specific API."""
        import requests
        
        if api_name == 'whoisfreaks':
            response = requests.get(
                f'https://api.whoisfreaks.com/v1.0/whois?apiKey={api_key}&whois=live&domainName={domain}',
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                raise ValueError(f"WhoisFreaks API error: {response.status_code}")
                
        elif api_name == 'securitytrails':
            response = requests.get(
                f'https://api.securitytrails.com/v1/domain/{domain}',
                headers={'APIKEY': api_key},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                raise ValueError(f"SecurityTrails API error: {response.status_code}")
                
        elif api_name == 'shodan':
            response = requests.get(
                f'https://api.shodan.io/dns/domain/{domain}?key={api_key}',
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                raise ValueError(f"Shodan API error: {response.status_code}")
        
        raise ValueError(f"Unknown API: {api_name}")
    
    def _get_c_module(self):
        """Load WHOIS fallback C module."""
        try:
            from c_fallback_modules.whois_lookup import WhoisLookup
            return WhoisLookup()
        except (ImportError, FileNotFoundError):
            return None
    
    def _c_fallback_scan(self, domain: str, **kwargs) -> Dict:
        """Use WHOIS fallback."""
        if self._c_module:
            return self._c_module.lookup(domain)
        return {'domain': domain, 'message': 'C module not available', 'source': 'fallback'}


class IPScanService(MultiAPIService):
    """IP scanning with multiple API fallbacks."""
    
    def __init__(self):
        super().__init__(
            primary_api='shodan',
            fallback_apis=['pulsedive', 'virustotal']
        )
    
    def _api_scan_with_key(self, ip: str, api_name: str, api_key: str, **kwargs) -> Dict:
        """Scan IP with specific API."""
        import requests
        
        if api_name == 'shodan':
            response = requests.get(
                f'https://api.shodan.io/shodan/host/{ip}?key={api_key}',
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                raise ValueError(f"Shodan API error: {response.status_code}")
                
        elif api_name == 'pulsedive':
            response = requests.get(
                f'https://pulsedive.com/api/info.php?indicator={ip}&key={api_key}',
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                raise ValueError(f"PulseDive API error: {response.status_code}")
                
        elif api_name == 'virustotal':
            response = requests.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                headers={'x-apikey': api_key},
                timeout=10
            )
            if response.status_code == 200:
                return response.json()
            else:
                raise ValueError(f"VirusTotal API error: {response.status_code}")
        
        raise ValueError(f"Unknown API: {api_name}")
    
    def _get_c_module(self):
        """Load network scanner C module."""
        try:
            from c_fallback_modules.network_scanner import PortScanner
            return PortScanner()
        except (ImportError, FileNotFoundError):
            return None
    
    def _c_fallback_scan(self, ip: str, **kwargs) -> Dict:
        """Use network scanner fallback."""
        if self._c_module:
            return self._c_module.scan(ip, ports='top100')
        return {'ip': ip, 'message': 'C module not available', 'source': 'fallback'}
