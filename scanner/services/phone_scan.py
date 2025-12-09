"""
Phone number scanning module.
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


class PhoneScanner:
    """Scans for phone number exposure."""
    
    def __init__(self, search_engine: SearchEngine = None):
        """Initialize phone scanner."""
        self.search_engine = search_engine or SearchEngine()
    
    def scan(self, phone: str) -> Dict:
        """
        Scan for phone number mentions.
        
        Args:
            phone: Phone number to search
        
        Returns:
            Dictionary with search results
        """
        if not phone:
            return {'results': [], 'count': 0}
        
        # Normalize phone number for search
        normalized = phone.replace('-', '').replace(' ', '').replace('(', '').replace(')', '')
        
        # Search for various formats
        queries = [
            f'"{phone}"',
            f'"{normalized}"',
            f'"{phone[:3]}-{phone[3:6]}-{phone[6:]}"' if len(normalized) == 10 else None
        ]
        
        all_results = []
        seen_links = set()
        
        for query in queries:
            if not query:
                continue
            results = self.search_engine.search(query, max_results=10)
            for result in results:
                if result['link'] not in seen_links:
                    all_results.append(result)
                    seen_links.add(result['link'])
        
        return {
            'results': all_results[:20],  # Limit to 20 unique results
            'count': len(all_results)
        }

