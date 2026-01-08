"""
IntelX API service for OSINT scanning.
"""
import os
import requests
from typing import Dict, List, Optional

# Try Django config first, fallback to Flask config
try:
    from scanner.services.config_helper import Config
except ImportError:
    try:
        from config import Config
    except ImportError:
        import os
        class Config:
            INTELX_API_KEY = os.getenv('INTELX_API_KEY')


class IntelXService:
    """Service for interacting with IntelX API."""
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize IntelX service.
        
        Args:
            api_key: IntelX API key (defaults to INTELX2_API_KEY or INTELX_API_KEY from config)
        """
        # Prioritize INTELX2_API_KEY, then INTELX_API_KEY
        self.api_key = api_key or getattr(Config, 'INTELX2_API_KEY', None) or os.getenv('INTELX2_API_KEY') or getattr(Config, 'INTELX_API_KEY', None) or os.getenv('INTELX_API_KEY')
        
        self.base_url = "https://2.intelx.io/intelligent/search"
        self.headers = {
            "x-key": self.api_key,
            "Content-Type": "application/json"
        } if self.api_key else {}
    
    def search(self, term: str, max_results: int = 20) -> Dict:
        """
        Perform a search on IntelX.
        
        Args:
            term: Search term
            max_results: Maximum number of results to return
            
        Returns:
            Dictionary with search results or empty dict on error
        """
        if not self.api_key:
            return {
                'success': False,
                'error': 'IntelX API key not configured',
                'results': []
            }
        
        if not term or not term.strip():
            return {
                'success': False,
                'error': 'Empty search term',
                'results': []
            }
        
        try:
            payload = {
                "term": term.strip(),
                "maxresults": max_results,
                "media": 0,  # 0 = all media types
                "target": 0,  # 0 = all targets
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
                    'success': True,
                    'results': data.get('selectors', []) or data.get('records', []),
                    'total': len(data.get('selectors', []) or data.get('records', [])),
                    'raw': data
                }
            elif response.status_code == 401:
                return {
                    'success': False,
                    'error': 'Invalid IntelX API key',
                    'results': []
                }
            elif response.status_code == 429:
                return {
                    'success': False,
                    'error': 'Rate limit exceeded',
                    'results': []
                }
            else:
                return {
                    'success': False,
                    'error': f'API returned status {response.status_code}',
                    'results': []
                }
        
        except requests.exceptions.RequestException as e:
            return {
                'success': False,
                'error': f'Request failed: {str(e)}',
                'results': []
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Unexpected error: {str(e)}',
                'results': []
            }
    
    def search_email(self, email: str, max_results: int = 20) -> Dict:
        """Search for email address."""
        if not email or '@' not in email:
            return {'success': False, 'error': 'Invalid email address', 'results': []}
        return self.search(email, max_results)
    
    def search_username(self, username: str, max_results: int = 20) -> Dict:
        """Search for username."""
        if not username or not username.strip():
            return {'success': False, 'error': 'Invalid username', 'results': []}
        return self.search(username, max_results)
    
    def search_phone(self, phone: str, max_results: int = 20) -> Dict:
        """Search for phone number."""
        if not phone or not phone.strip():
            return {'success': False, 'error': 'Invalid phone number', 'results': []}
        # Normalize: remove separators
        normalized = phone.strip().replace('-', '').replace(' ', '').replace('(', '').replace(')', '').replace('+', '')
        return self.search(normalized, max_results)
    
    def search_domain(self, domain: str, max_results: int = 20) -> Dict:
        """Search for domain."""
        if not domain or not domain.strip():
            return {'success': False, 'error': 'Invalid domain', 'results': []}
        # Remove protocol/path
        domain = domain.strip()
        if domain.startswith('http://') or domain.startswith('https://'):
            domain = domain.split('//', 1)[1]
        if '/' in domain:
            domain = domain.split('/')[0]
        return self.search(domain, max_results)
    
    def search_name(self, name: str, max_results: int = 20) -> Dict:
        """Search for full name."""
        if not name or not name.strip():
            return {'success': False, 'error': 'Invalid name', 'results': []}
        return self.search(f'"{name}"', max_results)

    def search_btc(self, btc_address: str, max_results: int = 20) -> Dict:
        """Search for Bitcoin address."""
        if not btc_address or not btc_address.strip():
            return {'success': False, 'error': 'Invalid BTC address', 'results': []}
        return self.search(btc_address.strip(), max_results)

    def search_ipfs(self, ipfs_hash: str, max_results: int = 20) -> Dict:
        """Search for IPFS hash."""
        if not ipfs_hash or not ipfs_hash.strip():
            return {'success': False, 'error': 'Invalid IPFS hash', 'results': []}
        return self.search(ipfs_hash.strip(), max_results)

    def search_cidr(self, cidr: str, max_results: int = 20) -> Dict:
        """Search for CIDR block or IP."""
        if not cidr or not cidr.strip():
            return {'success': False, 'error': 'Invalid CIDR/IP', 'results': []}
        return self.search(cidr.strip(), max_results)

