"""
IntelX API service for OSINT scanning.
"""
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
            api_key: IntelX API key (defaults to INTELX_API_KEY from config)
        """
        self.api_key = api_key or Config.INTELX_API_KEY
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
                    'results': data.get('selectors', []),
                    'total': len(data.get('selectors', [])),
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
        """
        Search for email address.
        
        Args:
            email: Email address to search
            max_results: Maximum results
            
        Returns:
            Dictionary with search results
        """
        if not email or '@' not in email:
            return {
                'success': False,
                'error': 'Invalid email address',
                'results': []
            }
        
        return self.search(email, max_results)
    
    def search_username(self, username: str, max_results: int = 20) -> Dict:
        """
        Search for username.
        
        Args:
            username: Username to search
            max_results: Maximum results
            
        Returns:
            Dictionary with search results
        """
        if not username or not username.strip():
            return {
                'success': False,
                'error': 'Invalid username',
                'results': []
            }
        
        return self.search(username, max_results)
    
    def search_phone(self, phone: str, max_results: int = 20) -> Dict:
        """
        Search for phone number.
        
        Args:
            phone: Phone number to search
            max_results: Maximum results
            
        Returns:
            Dictionary with search results
        """
        if not phone or not phone.strip():
            return {
                'success': False,
                'error': 'Invalid phone number',
                'results': []
            }
        
        # Normalize phone number (remove common separators)
        normalized = phone.strip().replace('-', '').replace(' ', '').replace('(', '').replace(')', '').replace('+', '')
        
        return self.search(normalized, max_results)
    
    def search_domain(self, domain: str, max_results: int = 20) -> Dict:
        """
        Search for domain.
        
        Args:
            domain: Domain to search
            max_results: Maximum results
            
        Returns:
            Dictionary with search results
        """
        if not domain or not domain.strip():
            return {
                'success': False,
                'error': 'Invalid domain',
                'results': []
            }
        
        # Remove protocol if present
        domain = domain.strip()
        if domain.startswith('http://') or domain.startswith('https://'):
            domain = domain.split('//', 1)[1]
        if '/' in domain:
            domain = domain.split('/')[0]
        
        return self.search(domain, max_results)
    
    def search_name(self, name: str, max_results: int = 20) -> Dict:
        """
        Search for full name.
        
        Args:
            name: Full name to search
            max_results: Maximum results
            
        Returns:
            Dictionary with search results
        """
        if not name or not name.strip():
            return {
                'success': False,
                'error': 'Invalid name',
                'results': []
            }
        
        return self.search(f'"{name}"', max_results)

