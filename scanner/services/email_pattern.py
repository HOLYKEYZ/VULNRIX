"""
Email pattern analysis module.
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


class EmailPatternAnalyzer:
    """Analyzes email patterns and exposure."""
    
    def __init__(self, search_engine: SearchEngine = None):
        """Initialize email pattern analyzer."""
        self.search_engine = search_engine or SearchEngine()
    
    def analyze(self, email: str) -> Dict:
        """
        Analyze email for patterns and exposure.
        
        Args:
            email: Email address to analyze
        
        Returns:
            Dictionary with analysis results
        """
        if not email or '@' not in email:
            return {}
        
        local_part, domain = email.split('@', 1)
        
        # Extract potential username patterns
        patterns = {
            'local_part': local_part,
            'domain': domain,
            'potential_usernames': []
        }
        
        # Check if local part could be a username
        if local_part:
            patterns['potential_usernames'].append(local_part)
        
        # Check for email in various contexts
        queries = [
            f'"{email}"',
            f'"{local_part}" "{domain}"',
            f'email "{email}"'
        ]
        
        all_results = []
        seen_links = set()
        
        for query in queries:
            results = self.search_engine.search(query, max_results=10)
            for result in results:
                if result['link'] not in seen_links:
                    all_results.append(result)
                    seen_links.add(result['link'])
        
        patterns['exposure_results'] = all_results[:20]
        patterns['exposure_count'] = len(all_results)
        
        return patterns

