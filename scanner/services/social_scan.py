"""
Social media scanning module.
"""
from typing import Dict, List, Optional

# Try Django services first, fallback to Flask modules
try:
    from scanner.services.search_engine import SearchEngine
except ImportError:
    try:
        from app.scanner.modules.search_engine import SearchEngine
    except ImportError:
        from search_engine import SearchEngine


class SocialScanner:
    """Scans social media platforms for user presence."""
    
    def __init__(self, search_engine: SearchEngine = None):
        """Initialize social scanner."""
        self.search_engine = search_engine or SearchEngine()
        self.platforms = {
            'instagram': 'instagram.com',
            'tiktok': 'tiktok.com',
            'twitter': 'twitter.com',
            'facebook': 'facebook.com',
            'reddit': 'reddit.com',
            'github': 'github.com',
            'snapchat': 'snapchat.com',
            'threads': 'threads.net'
        }
    
    def scan_platform(self, username: str, platform: str) -> List[Dict]:
        """
        Scan a specific platform for username.
        
        Args:
            username: Username to search
            platform: Platform name (e.g., 'instagram')
        
        Returns:
            List of search results
        """
        if platform not in self.platforms:
            return []
        
        domain = self.platforms[platform]
        query = f'site:{domain} "{username}"'
        results = self.search_engine.search(query, max_results=10)
        
        return results
    
    def scan_all(self, username: str, selected_platforms: List[str] = None) -> Dict[str, List[Dict]]:
        """
        Scan multiple platforms for username.
        
        Args:
            username: Username to search
            selected_platforms: List of platform names to scan (None = all)
        
        Returns:
            Dictionary mapping platform names to results
        """
        if not username:
            return {}
        
        if selected_platforms is None:
            selected_platforms = list(self.platforms.keys())
        
        results = {}
        for platform in selected_platforms:
            if platform in self.platforms:
                results[platform] = self.scan_platform(username, platform)
        
        return results

