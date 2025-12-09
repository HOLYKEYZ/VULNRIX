"""
API Health Checker - Tests API availability before use.
Determines when to switch to C fallback implementations.
"""

import os
import time
import logging
import requests
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from threading import Lock

logger = logging.getLogger('vulnrix.fallback')


class APIHealthChecker:
    """
    Checks API health and determines when to use C fallback.
    Implements caching to avoid excessive health checks.
    """
    
    # Cache duration for health check results (seconds)
    CACHE_DURATION = 300  # 5 minutes
    
    # API configurations - all available API keys
    API_CONFIGS = {
        'google_search': {
            'env_keys': ['GOOGLE_API_KEY'],
            'extra_keys': ['CSE_ID'],
            'health_url': 'https://www.googleapis.com/customsearch/v1',
            'rate_limit_header': None,
            'daily_quota': 100,
            'fallback_apis': [],
        },
        'intelx': {
            'env_keys': ['INTELX_API_KEY'],
            'health_url': 'https://2.intelx.io/authenticate/info',
            'rate_limit_header': 'X-RateLimit-Remaining',
            'daily_quota': None,
            'fallback_apis': [],
        },
        'grok': {
            'env_keys': ['GROK_API_KEY'],
            'health_url': None,
            'rate_limit_header': None,
            'daily_quota': None,
            'fallback_apis': [],
        },
        'leakinsight': {
            'env_keys': ['LEAKINSIGHT_API_KEY'],
            'health_url': None,
            'rate_limit_header': None,
            'daily_quota': None,
            'fallback_apis': ['leak_lookup'],
        },
        'leak_lookup': {
            'env_keys': ['LEAK_LOOKUP_API_KEY'],
            'health_url': None,
            'rate_limit_header': None,
            'daily_quota': None,
            'fallback_apis': [],
        },
        'virustotal': {
            'env_keys': ['VIRUS_TOTAL_API_KEY'],
            'health_url': 'https://www.virustotal.com/api/v3/users/current',
            'rate_limit_header': 'X-Api-Quota-Remaining',
            'daily_quota': 500,
            'fallback_apis': [],
        },
        'shodan': {
            'env_keys': ['SHODAN_API_KEY', 'SHODAN_API_KEY_2'],
            'health_url': 'https://api.shodan.io/api-info',
            'rate_limit_header': None,
            'daily_quota': None,
            'fallback_apis': ['pulsedive'],
        },
        'pulsedive': {
            'env_keys': ['PULSE_DIVE_API_KEY'],
            'health_url': 'https://pulsedive.com/api/info.php',
            'rate_limit_header': None,
            'daily_quota': None,
            'fallback_apis': [],
        },
        'whoisfreaks': {
            'env_keys': ['WHO_IS_FREAKS_API_KEY'],
            'health_url': 'https://api.whoisfreaks.com/v1.0/whois',
            'rate_limit_header': 'X-RateLimit-Remaining',
            'daily_quota': None,
            'fallback_apis': ['securitytrails'],
        },
        'securitytrails': {
            'env_keys': ['SECURITY_TRAILS_API_KEY'],
            'health_url': 'https://api.securitytrails.com/v1/ping',
            'rate_limit_header': 'X-RateLimit-Remaining',
            'daily_quota': 50,
            'fallback_apis': [],
        },
        'dymo': {
            'env_keys': ['DYMO_API_KEY'],
            'health_url': None,
            'rate_limit_header': None,
            'daily_quota': None,
            'fallback_apis': [],
        },
        'numlookup': {
            'env_keys': ['NUMLOOKUP_API_KEY'],
            'health_url': None,
            'rate_limit_header': None,
            'daily_quota': None,
            'fallback_apis': ['veriphone'],
        },
        'veriphone': {
            'env_keys': ['VERIPHONE_API_KEY'],
            'health_url': None,
            'rate_limit_header': None,
            'daily_quota': None,
            'fallback_apis': [],
        },
        'groq': {
            'env_keys': ['GROQ_KEY'],
            'health_url': None,
            'rate_limit_header': None,
            'daily_quota': None,
            'fallback_apis': [],
        },
        'snyk': {
            'env_keys': ['SNYK_API_KEY'],
            'health_url': 'https://api.snyk.io/rest/self',
            'rate_limit_header': None,
            'daily_quota': None,
            'fallback_apis': [],
        },
    }
    
    def __init__(self):
        self._cache: Dict[str, Dict] = {}
        self._cache_lock = Lock()
        self._usage_counts: Dict[str, int] = {}
        self._failure_counts: Dict[str, int] = {}
        self._last_reset = datetime.now()
    
    def _get_api_key(self, api_name: str) -> Optional[str]:
        """Get API key from environment."""
        config = self.API_CONFIGS.get(api_name, {})
        env_keys = config.get('env_keys', [])
        
        for key in env_keys:
            value = os.getenv(key)
            if value and value.strip():
                return value.strip()
        return None
    
    def _is_cache_valid(self, api_name: str) -> bool:
        """Check if cached health status is still valid."""
        with self._cache_lock:
            if api_name not in self._cache:
                return False
            cached = self._cache[api_name]
            return (datetime.now() - cached['timestamp']).seconds < self.CACHE_DURATION
    
    def _get_cached_status(self, api_name: str) -> Optional[Dict]:
        """Get cached health status."""
        with self._cache_lock:
            if self._is_cache_valid(api_name):
                return self._cache[api_name]['status']
        return None
    
    def _cache_status(self, api_name: str, status: Dict):
        """Cache health status."""
        with self._cache_lock:
            self._cache[api_name] = {
                'status': status,
                'timestamp': datetime.now()
            }

    def check_api_status(self, api_name: str, force_check: bool = False) -> Dict:
        """
        Check API availability and health.
        
        Args:
            api_name: Name of the API to check
            force_check: Skip cache and force fresh check
            
        Returns:
            {
                "available": bool,
                "reason": str,  # "ok", "rate_limited", "invalid_key", "timeout", "no_key"
                "fallback_needed": bool,
                "fallback_apis": list,  # Alternative APIs to try first
                "quota_remaining": int or None,
                "checked_at": datetime
            }
        """
        # Check cache first
        if not force_check:
            cached = self._get_cached_status(api_name)
            if cached:
                return cached
        
        config = self.API_CONFIGS.get(api_name)
        if not config:
            return self._make_status(False, 'unknown_api', True, [])
        
        # Check if API key exists
        api_key = self._get_api_key(api_name)
        if not api_key:
            status = self._make_status(False, 'no_key', True, config.get('fallback_apis', []))
            self._cache_status(api_name, status)
            return status
        
        # Perform health check based on API type
        try:
            status = self._perform_health_check(api_name, api_key, config)
        except Exception as e:
            logger.error(f"Health check failed for {api_name}: {e}")
            status = self._make_status(False, 'check_failed', True, config.get('fallback_apis', []))
        
        self._cache_status(api_name, status)
        return status
    
    def _perform_health_check(self, api_name: str, api_key: str, config: Dict) -> Dict:
        """Perform actual health check for specific API."""
        fallback_apis = config.get('fallback_apis', [])
        
        # API-specific health checks
        if api_name == 'google_search':
            return self._check_google(api_key)
        elif api_name == 'intelx':
            return self._check_intelx(api_key)
        elif api_name == 'virustotal':
            return self._check_virustotal(api_key)
        elif api_name == 'shodan':
            return self._check_shodan(api_key)
        elif api_name == 'securitytrails':
            return self._check_securitytrails(api_key)
        elif api_name == 'whoisfreaks':
            return self._check_whoisfreaks(api_key)
        elif api_name == 'pulsedive':
            return self._check_pulsedive(api_key)
        elif api_name == 'snyk':
            return self._check_snyk(api_key)
        else:
            # Generic check - just verify key exists (for APIs without health endpoints)
            return self._make_status(True, 'ok', False, fallback_apis)
    
    def _check_google(self, api_key: str) -> Dict:
        """Check Google Custom Search API."""
        cse_id = os.getenv('CSE_ID')
        if not cse_id:
            return self._make_status(False, 'no_cse_id', True, [])
        
        try:
            # Light check - just verify credentials work
            resp = requests.get(
                'https://www.googleapis.com/customsearch/v1',
                params={'key': api_key, 'cx': cse_id, 'q': 'test', 'num': 1},
                timeout=10
            )
            
            if resp.status_code == 200:
                return self._make_status(True, 'ok', False, [])
            elif resp.status_code == 403:
                data = resp.json()
                if 'quota' in str(data).lower():
                    return self._make_status(False, 'quota_exceeded', True, [])
                return self._make_status(False, 'invalid_key', True, [])
            elif resp.status_code == 429:
                return self._make_status(False, 'rate_limited', True, [])
            else:
                return self._make_status(False, f'error_{resp.status_code}', True, [])
        except requests.Timeout:
            return self._make_status(False, 'timeout', True, [])
        except Exception as e:
            return self._make_status(False, 'error', True, [])
    
    def _check_intelx(self, api_key: str) -> Dict:
        """Check IntelX API."""
        try:
            resp = requests.get(
                'https://2.intelx.io/authenticate/info',
                headers={'x-key': api_key},
                timeout=10
            )
            
            if resp.status_code == 200:
                data = resp.json()
                # Check remaining credits
                credits = data.get('credits', {}).get('remaining', 0)
                if credits <= 0:
                    return self._make_status(False, 'no_credits', True, [], quota_remaining=0)
                return self._make_status(True, 'ok', False, [], quota_remaining=credits)
            elif resp.status_code == 401:
                return self._make_status(False, 'invalid_key', True, [])
            elif resp.status_code == 429:
                return self._make_status(False, 'rate_limited', True, [])
            else:
                return self._make_status(False, f'error_{resp.status_code}', True, [])
        except requests.Timeout:
            return self._make_status(False, 'timeout', True, [])
        except Exception:
            return self._make_status(False, 'error', True, [])
    
    def _check_hibp(self, api_key: str, fallback_apis: list) -> Dict:
        """Check HaveIBeenPwned API."""
        try:
            resp = requests.get(
                'https://haveibeenpwned.com/api/v3/breaches',
                headers={'hibp-api-key': api_key},
                timeout=10
            )
            
            if resp.status_code == 200:
                return self._make_status(True, 'ok', False, fallback_apis)
            elif resp.status_code == 401:
                return self._make_status(False, 'invalid_key', True, fallback_apis)
            elif resp.status_code == 429:
                retry_after = resp.headers.get('Retry-After', 60)
                return self._make_status(False, 'rate_limited', True, fallback_apis)
            else:
                return self._make_status(False, f'error_{resp.status_code}', True, fallback_apis)
        except requests.Timeout:
            return self._make_status(False, 'timeout', True, fallback_apis)
        except Exception:
            return self._make_status(False, 'error', True, fallback_apis)
    
    def _check_virustotal(self, api_key: str) -> Dict:
        """Check VirusTotal API."""
        try:
            resp = requests.get(
                'https://www.virustotal.com/api/v3/users/current',
                headers={'x-apikey': api_key},
                timeout=10
            )
            
            if resp.status_code == 200:
                data = resp.json()
                quotas = data.get('data', {}).get('attributes', {}).get('quotas', {})
                daily = quotas.get('api_requests_daily', {})
                remaining = daily.get('allowed', 0) - daily.get('used', 0)
                
                if remaining <= 10:
                    return self._make_status(False, 'quota_low', True, [], quota_remaining=remaining)
                return self._make_status(True, 'ok', False, [], quota_remaining=remaining)
            elif resp.status_code == 401:
                return self._make_status(False, 'invalid_key', True, [])
            elif resp.status_code == 429:
                return self._make_status(False, 'rate_limited', True, [])
            else:
                return self._make_status(False, f'error_{resp.status_code}', True, [])
        except requests.Timeout:
            return self._make_status(False, 'timeout', True, [])
        except Exception:
            return self._make_status(False, 'error', True, [])
    
    def _get_all_api_keys(self, api_name: str) -> list:
        """Get all available API keys for an API (for rotation)."""
        config = self.API_CONFIGS.get(api_name, {})
        env_keys = config.get('env_keys', [])
        keys = []
        for key in env_keys:
            value = os.getenv(key)
            if value and value.strip():
                keys.append(value.strip())
        return keys
    
    def _check_shodan(self, api_key: str) -> Dict:
        """Check Shodan API - tries all available keys."""
        keys_to_try = self._get_all_api_keys('shodan')
        if not keys_to_try:
            return self._make_status(False, 'no_key', True, [])
        
        for key in keys_to_try:
            try:
                resp = requests.get(
                    f'https://api.shodan.io/api-info?key={key}',
                    timeout=10
                )
                
                if resp.status_code == 200:
                    data = resp.json()
                    credits = data.get('query_credits', 0)
                    if credits > 0:
                        return self._make_status(True, 'ok', False, [], quota_remaining=credits)
            except:
                continue
        
        return self._make_status(False, 'all_keys_failed', True, [])
    
    def _check_securitytrails(self, api_key: str) -> Dict:
        """Check SecurityTrails API."""
        try:
            resp = requests.get(
                'https://api.securitytrails.com/v1/ping',
                headers={'APIKEY': api_key},
                timeout=10
            )
            
            if resp.status_code == 200:
                remaining = resp.headers.get('X-RateLimit-Remaining')
                return self._make_status(True, 'ok', False, [], 
                    quota_remaining=int(remaining) if remaining else None)
            elif resp.status_code == 401:
                return self._make_status(False, 'invalid_key', True, [])
            elif resp.status_code == 429:
                return self._make_status(False, 'rate_limited', True, [])
            else:
                return self._make_status(False, f'error_{resp.status_code}', True, [])
        except requests.Timeout:
            return self._make_status(False, 'timeout', True, [])
        except Exception:
            return self._make_status(False, 'error', True, [])
    
    def _check_whoisfreaks(self, api_key: str) -> Dict:
        """Check WhoisFreaks API."""
        try:
            resp = requests.get(
                f'https://api.whoisfreaks.com/v1.0/whois?apiKey={api_key}&whois=live&domainName=example.com',
                timeout=10
            )
            
            if resp.status_code == 200:
                return self._make_status(True, 'ok', False, [])
            elif resp.status_code == 401:
                return self._make_status(False, 'invalid_key', True, [])
            elif resp.status_code == 429:
                return self._make_status(False, 'rate_limited', True, [])
            else:
                return self._make_status(False, f'error_{resp.status_code}', True, [])
        except requests.Timeout:
            return self._make_status(False, 'timeout', True, [])
        except Exception:
            return self._make_status(False, 'error', True, [])
    
    def _check_pulsedive(self, api_key: str) -> Dict:
        """Check PulseDive API."""
        try:
            resp = requests.get(
                f'https://pulsedive.com/api/info.php?key={api_key}',
                timeout=10
            )
            
            if resp.status_code == 200:
                return self._make_status(True, 'ok', False, [])
            elif resp.status_code == 401:
                return self._make_status(False, 'invalid_key', True, [])
            else:
                return self._make_status(False, f'error_{resp.status_code}', True, [])
        except requests.Timeout:
            return self._make_status(False, 'timeout', True, [])
        except Exception:
            return self._make_status(False, 'error', True, [])
    
    def _check_snyk(self, api_key: str) -> Dict:
        """Check Snyk API for code vulnerability scanning."""
        try:
            resp = requests.get(
                'https://api.snyk.io/rest/self?version=2024-04-29',
                headers={'Authorization': f'token {api_key}'},
                timeout=10
            )
            
            if resp.status_code == 200:
                return self._make_status(True, 'ok', False, [])
            elif resp.status_code == 401:
                return self._make_status(False, 'invalid_key', True, [])
            elif resp.status_code == 429:
                return self._make_status(False, 'rate_limited', True, [])
            else:
                return self._make_status(False, f'error_{resp.status_code}', True, [])
        except requests.Timeout:
            return self._make_status(False, 'timeout', True, [])
        except Exception:
            return self._make_status(False, 'error', True, [])
    
    def _make_status(self, available: bool, reason: str, fallback_needed: bool, 
                     fallback_apis: list, quota_remaining: int = None) -> Dict:
        """Create standardized status response."""
        return {
            'available': available,
            'reason': reason,
            'fallback_needed': fallback_needed,
            'fallback_apis': fallback_apis,
            'quota_remaining': quota_remaining,
            'checked_at': datetime.now().isoformat()
        }
    
    def should_use_fallback(self, api_name: str) -> Tuple[bool, str]:
        """
        Determine if C fallback should be used.
        
        Returns:
            (should_fallback: bool, reason: str)
        """
        status = self.check_api_status(api_name)
        
        if not status['available']:
            # Try fallback APIs first
            for fallback_api in status.get('fallback_apis', []):
                fallback_status = self.check_api_status(fallback_api)
                if fallback_status['available']:
                    return (False, f'using_fallback_api:{fallback_api}')
            
            return (True, status['reason'])
        
        return (False, 'api_available')
    
    def record_api_failure(self, api_name: str):
        """Record an API failure for tracking."""
        with self._cache_lock:
            self._failure_counts[api_name] = self._failure_counts.get(api_name, 0) + 1
    
    def record_api_usage(self, api_name: str):
        """Record API usage for tracking."""
        with self._cache_lock:
            self._usage_counts[api_name] = self._usage_counts.get(api_name, 0) + 1
    
    def get_stats(self) -> Dict:
        """Get API health statistics."""
        with self._cache_lock:
            return {
                'usage_counts': dict(self._usage_counts),
                'failure_counts': dict(self._failure_counts),
                'cached_statuses': {k: v['status'] for k, v in self._cache.items()}
            }
