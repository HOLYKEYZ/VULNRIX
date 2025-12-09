"""
Search engine module for web searches.
"""
import requests
import time
from typing import List, Dict, Optional

# Try Django config first, fallback to Flask config
try:
    from scanner.services.config_helper import Config
except ImportError:
    try:
        from config import Config
    except ImportError:
        import os
        class Config:
            GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')
            CSE_ID = os.getenv('CSE_ID')


class SearchEngine:
    """Handles Google Custom Search API queries."""
    
    def __init__(self, api_key: str = None, search_engine_id: str = None):
        """Initialize the search engine."""
        self.api_key = api_key or Config.GOOGLE_API_KEY
        self.search_engine_id = search_engine_id or Config.CSE_ID
        self.base_url = "https://www.googleapis.com/customsearch/v1"
    
    def search(self, query: str, max_results: int = 10) -> List[Dict]:
        """
        Search for a query using Google Custom Search API.
        
        Args:
            query: Search query string
            max_results: Maximum number of results to return (default: 10, max: 100)
        
        Returns:
            List of dictionaries containing search results
        """
        if not self.api_key or not self.search_engine_id:
            return []
        
        max_results = min(max_results, 100)
        results = []
        start_index = 1
        max_pages = 10
        
        try:
            while len(results) < max_results and start_index <= (max_pages * 10):
                results_per_page = min(10, max_results - len(results))
                
                params = {
                    'key': self.api_key,
                    'cx': self.search_engine_id,
                    'q': query,
                    'start': start_index,
                    'num': results_per_page
                }
                
                response = requests.get(self.base_url, params=params, timeout=15)
                response.raise_for_status()
                
                data = response.json()
                
                if 'items' in data:
                    for item in data['items']:
                        result = {
                            'title': item.get('title', 'No title'),
                            'link': item.get('link', ''),
                            'snippet': item.get('snippet', 'No snippet available'),
                            'displayLink': item.get('displayLink', ''),
                            'formattedUrl': item.get('formattedUrl', '')
                        }
                        results.append(result)
                
                has_next_page = False
                if 'queries' in data and 'nextPage' in data['queries']:
                    next_page_info = data['queries']['nextPage'][0]
                    next_start = next_page_info.get('startIndex', 0)
                    if next_start > start_index and len(results) < max_results:
                        start_index = next_start
                        has_next_page = True
                
                if not has_next_page or len(results) >= max_results:
                    break
                
                time.sleep(0.1)
            
            return results[:max_results]
        
        except Exception:
            return []
    
    def find_mentions(self, name: Optional[str] = None, 
                     email: Optional[str] = None, 
                     username: Optional[str] = None,
                     max_results_per_type: int = 10) -> Dict[str, List[Dict]]:
        """
        Find online mentions of the provided information.
        
        Args:
            name: Name to search for
            email: Email to search for
            username: Username to search for
            max_results_per_type: Maximum results per search type
        
        Returns:
            Dictionary with keys 'name', 'email', 'username' containing search results
        """
        all_results = {
            'name': [],
            'email': [],
            'username': []
        }
        
        if name:
            name_results = self.search(f'"{name}"', max_results=max_results_per_type)
            all_results['name'] = name_results
        
        if email:
            email_results = self.search(f'"{email}"', max_results=max_results_per_type)
            all_results['email'] = email_results
        
        if username:
            username_results = self.search(f'"{username}"', max_results=max_results_per_type)
            all_results['username'] = username_results
        
        return all_results

