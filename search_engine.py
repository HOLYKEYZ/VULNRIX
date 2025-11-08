"""
Google Custom Search Engine integration for finding online mentions.
"""

import requests
import json
import time
from typing import List, Dict, Optional
from utils.display import print_warning, print_danger, print_info


class SearchEngine:
    """Handles Google Custom Search API queries."""
    
    def __init__(self, api_key: str, search_engine_id: str):
        """
        Initialize the search engine.
        
        Args:
            api_key: Google Custom Search API key
            search_engine_id: Custom Search Engine ID
        """
        self.api_key = api_key
        self.search_engine_id = search_engine_id
        self.base_url = "https://www.googleapis.com/customsearch/v1"
    
    def search(self, query: str, max_results: int = 10) -> List[Dict]:
        """
        Search for a query using Google Custom Search API with pagination support.
        
        Args:
            query: Search query string
            max_results: Maximum number of results to return (default: 10, max: 100)
        
        Returns:
            List of dictionaries containing search results with 'title', 'link', and 'snippet'
        """
        if not self.api_key or self.api_key == "YOUR_API_KEY_HERE":
            print_warning("⚠️  Google API key not configured. Skipping web search.")
            return []
        
        if not self.search_engine_id or self.search_engine_id == "YOUR_SEARCH_ENGINE_ID_HERE":
            print_warning("⚠️  Search Engine ID not configured. Skipping web search.")
            print_info("💡 To use web search, create a Custom Search Engine at:")
            print_info("   https://programmablesearchengine.google.com/")
            return []
        
        # Limit max_results to API maximum (100 results)
        max_results = min(max_results, 100)
        results = []
        start_index = 1
        max_pages = 10  # Google Custom Search API allows max 10 pages (100 results)
        
        try:
            while len(results) < max_results and start_index <= (max_pages * 10):
                # Calculate how many results to request for this page
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
                
                # Extract results from this page
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
                
                # Check if there are more results available
                has_next_page = False
                if 'queries' in data:
                    if 'nextPage' in data['queries']:
                        next_page_info = data['queries']['nextPage'][0]
                        next_start = next_page_info.get('startIndex', 0)
                        if next_start > start_index and len(results) < max_results:
                            start_index = next_start
                            has_next_page = True
                
                # Break if no more pages or we have enough results
                if not has_next_page or len(results) >= max_results:
                    break
                
                # Small delay to respect API rate limits
                time.sleep(0.1)
            
            return results[:max_results]
        
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400:
                print_danger(f"❌ Invalid API request. Check your API key and Search Engine ID.")
            elif e.response.status_code == 403:
                print_danger(f"❌ API access denied. Check your API key permissions and quota.")
            elif e.response.status_code == 429:
                print_warning("⚠️  API rate limit exceeded. Please wait before trying again.")
            else:
                print_danger(f"❌ HTTP error {e.response.status_code}: {str(e)}")
            return []
        except requests.exceptions.RequestException as e:
            print_danger(f"❌ Error connecting to Google Custom Search API: {str(e)}")
            return []
        except json.JSONDecodeError as e:
            print_danger(f"❌ Error parsing API response: {str(e)}")
            return []
        except KeyError as e:
            print_danger(f"❌ Unexpected API response format: {str(e)}")
            return []
        except Exception as e:
            print_danger(f"❌ Unexpected error during search: {str(e)}")
            return []
    
    def find_mentions(self, name: Optional[str] = None, 
                     email: Optional[str] = None, 
                     username: Optional[str] = None,
                     max_results_per_type: int = 10) -> Dict[str, List[Dict]]:
        """
        Find online mentions of the provided information.
        Modular function that queries the API with user input and returns structured results.
        
        Args:
            name: Name to search for
            email: Email to search for
            username: Username to search for
            max_results_per_type: Maximum results per search type (default: 10, max: 100)
        
        Returns:
            Dictionary with keys 'name', 'email', 'username' containing structured search results.
            Each result contains: 'title', 'link', 'snippet', 'displayLink', 'formattedUrl'
        """
        all_results = {
            'name': [],
            'email': [],
            'username': []
        }
        
        # Search for name mentions
        if name:
            print_info(f"🔍 Searching for name: {name}")
            name_results = self.search(f'"{name}"', max_results=max_results_per_type)
            all_results['name'] = name_results
            if name_results:
                print_info(f"   Found {len(name_results)} result(s)")
        
        # Search for email mentions (more sensitive, so we search carefully)
        if email:
            print_info(f"🔍 Searching for email: {email}")
            email_results = self.search(f'"{email}"', max_results=max_results_per_type)
            all_results['email'] = email_results
            if email_results:
                print_warning(f"   ⚠️  Found {len(email_results)} result(s) - Email exposure detected!")
        
        # Search for username mentions
        if username:
            print_info(f"🔍 Searching for username: {username}")
            username_results = self.search(f'"{username}"', max_results=max_results_per_type)
            all_results['username'] = username_results
            if username_results:
                print_info(f"   Found {len(username_results)} result(s)")
        
        return all_results

