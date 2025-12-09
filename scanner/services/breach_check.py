"""
Breach Checker Service - Uses LeakInsight with IntelX fallback.
Replaces HIBP implementation.
"""
import requests
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)

# Try Django config first, fallback to Flask config
try:
    from scanner.services.config_helper import Config
except ImportError:
    try:
        from config import Config
    except ImportError:
        import os
        class Config:
            LEAKINSIGHT_API_KEY = os.getenv('LEAKINSIGHT_API_KEY')
            LEAK_LOOKUP_API_KEY = os.getenv('LEAK_LOOKUP_API_KEY')
            INTELX_API_KEY = os.getenv('INTELX_API_KEY')


class BreachChecker:
    """
    Handles breach checking using multiple APIs with fallback.
    
    Priority order:
    1. LeakInsight (primary)
    2. LeakLookup (fallback 1)
    3. IntelX (fallback 2)
    """
    
    def __init__(self):
        """Initialize the breach checker with API keys."""
        self.leakinsight_key = getattr(Config, 'LEAKINSIGHT_API_KEY', None)
        self.leaklookup_key = getattr(Config, 'LEAK_LOOKUP_API_KEY', None)
        self.intelx_key = getattr(Config, 'INTELX_API_KEY', None)
    
    def check_email(self, email: str) -> Dict:
        """
        Check if an email has been involved in data breaches.
        Uses fallback chain: LeakInsight -> LeakLookup -> IntelX
        
        Args:
            email: Email address to check
        
        Returns:
            Dictionary with 'breaches' list and 'total_breaches' count
        """
        if not email or '@' not in email:
            return {'breaches': [], 'total_breaches': 0, 'source': 'invalid_input'}
        
        # Try LeakInsight first
        if self.leakinsight_key:
            result = self._check_leakinsight(email)
            if result.get('success'):
                return result
            logger.warning(f"LeakInsight failed, trying fallback: {result.get('error')}")
        
        # Fallback to LeakLookup
        if self.leaklookup_key:
            result = self._check_leaklookup(email)
            if result.get('success'):
                return result
            logger.warning(f"LeakLookup failed, trying fallback: {result.get('error')}")
        
        # Fallback to IntelX
        if self.intelx_key:
            result = self._check_intelx(email)
            if result.get('success'):
                return result
            logger.warning(f"IntelX failed: {result.get('error')}")
        
        # All APIs failed
        return {
            'breaches': [],
            'total_breaches': 0,
            'source': 'no_api_available',
            'error': 'All breach checking APIs failed or not configured'
        }
    
    def _check_leakinsight(self, email: str) -> Dict:
        """Check email using LeakInsight API."""
        try:
            response = requests.get(
                f"https://leakinsight.io/api/v1/lookup/{email}",
                headers={'Authorization': f'Bearer {self.leakinsight_key}'},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                breaches = data.get('breaches', [])
                return {
                    'success': True,
                    'breaches': breaches,
                    'total_breaches': len(breaches),
                    'source': 'leakinsight'
                }
            elif response.status_code == 404:
                return {
                    'success': True,
                    'breaches': [],
                    'total_breaches': 0,
                    'source': 'leakinsight'
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned {response.status_code}',
                    'breaches': [],
                    'total_breaches': 0
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'breaches': [],
                'total_breaches': 0
            }
    
    def _check_leaklookup(self, email: str) -> Dict:
        """Check email using LeakLookup API."""
        try:
            response = requests.post(
                "https://leak-lookup.com/api/search",
                data={'key': self.leaklookup_key, 'type': 'email_address', 'query': email},
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('error') == 'false':
                    message = data.get('message', {})
                    breaches = []
                    for source, entries in message.items():
                        for entry in entries if isinstance(entries, list) else [entries]:
                            breaches.append({
                                'source': source,
                                'data': entry
                            })
                    return {
                        'success': True,
                        'breaches': breaches,
                        'total_breaches': len(breaches),
                        'source': 'leaklookup'
                    }
            return {
                'success': False,
                'error': 'API error',
                'breaches': [],
                'total_breaches': 0
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'breaches': [],
                'total_breaches': 0
            }
    
    def _check_intelx(self, email: str) -> Dict:
        """Check email using IntelX API."""
        try:
            response = requests.post(
                "https://2.intelx.io/intelligent/search",
                headers={'x-key': self.intelx_key, 'Content-Type': 'application/json'},
                json={'term': email, 'maxresults': 50, 'media': 0, 'target': 0},
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                selectors = data.get('selectors', [])
                breaches = [{'source': 'intelx', 'data': s} for s in selectors]
                return {
                    'success': True,
                    'breaches': breaches,
                    'total_breaches': len(breaches),
                    'source': 'intelx'
                }
            return {
                'success': False,
                'error': f'API returned {response.status_code}',
                'breaches': [],
                'total_breaches': 0
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'breaches': [],
                'total_breaches': 0
            }
