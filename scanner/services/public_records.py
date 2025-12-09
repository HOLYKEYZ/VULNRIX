"""
Public records scanning module.
"""
from typing import Dict, Optional

# Try Django services first, fallback to Flask modules
try:
    from scanner.services.search_engine import SearchEngine
except ImportError:
    try:
        from app.scanner.modules.search_engine import SearchEngine
    except ImportError:
        from search_engine import SearchEngine


class PublicRecordsScanner:
    """Scans for public records exposure."""
    
    def __init__(self, search_engine: SearchEngine = None):
        """Initialize public records scanner."""
        self.search_engine = search_engine or SearchEngine()
        self.record_sites = [
            'whitepages.com',
            'spokeo.com',
            'beenverified.com',
            'truthfinder.com',
            'intelius.com',
            'peoplefinder.com'
        ]
    
    def scan(self, name: str, email: Optional[str] = None, phone: Optional[str] = None) -> Dict:
        """
        Scan for public records.
        
        Args:
            name: Full name to search
            email: Optional email
            phone: Optional phone number
        
        Returns:
            Dictionary with public records findings
        """
        if not name:
            return {'results': [], 'sites_found': []}
        
        all_results = []
        sites_found = []
        seen_links = set()
        
        # Search for name on public records sites
        for site in self.record_sites:
            query = f'site:{site} "{name}"'
            results = self.search_engine.search(query, max_results=5)
            
            for result in results:
                if result['link'] not in seen_links:
                    all_results.append(result)
                    seen_links.add(result['link'])
                    if site not in sites_found:
                        sites_found.append(site)
        
        return {
            'results': all_results[:20],
            'sites_found': sites_found,
            'count': len(all_results)
        }

