"""
Dark web scanning module - Uses multiple APIs to check for dark web exposure.
"""
import os
import requests
import logging
from typing import Dict, Optional, List

logger = logging.getLogger('vulnrix.darkweb')

# Try Django config first, fallback to Flask config
try:
    from scanner.services.config_helper import Config
except ImportError:
    try:
        from config import Config
    except ImportError:
        class Config:
            INTELX_API_KEY = os.getenv('INTELX_API_KEY')
            LEAKINSIGHT_API_KEY = os.getenv('LEAKINSIGHT_API_KEY')
            LEAK_LOOKUP_API_KEY = os.getenv('LEAK_LOOKUP_API_KEY')


class DarkWebScanner:
    """Scans dark web for exposed data using multiple APIs."""
    
    def __init__(self):
        """Initialize dark web scanner with API keys."""
        self.intelx_api_key = getattr(Config, 'INTELX_API_KEY', None) or os.getenv('INTELX_API_KEY')
        self.leakinsight_key = getattr(Config, 'LEAKINSIGHT_API_KEY', None) or os.getenv('LEAKINSIGHT_API_KEY')
        self.leak_lookup_key = getattr(Config, 'LEAK_LOOKUP_API_KEY', None) or os.getenv('LEAK_LOOKUP_API_KEY')
    
    def scan(self, email: Optional[str] = None, phone: Optional[str] = None,
             name: Optional[str] = None, username: Optional[str] = None,
             domain: Optional[str] = None, ip: Optional[str] = None) -> Dict:
        """
        Scan dark web for exposed data using multiple sources.
        
        Args:
            email: Email to check
            phone: Phone number to check
            name: Full name to check
            username: Username to check
            domain: Domain to check
            ip: IP address to check
        
        Returns:
            Dictionary with dark web exposure results
        """
        results = {
            'breaches': [],
            'pastes': [],
            'dark_web_mentions': [],
            'leak_databases': [],
            'exposure_score': 0,
            'sources_checked': [],
            'recommendations': []
        }
        
        if email:
            # Check IntelX for dark web mentions
            intelx_results = self._check_intelx(email)
            if intelx_results:
                results['dark_web_mentions'].extend(intelx_results)
                results['sources_checked'].append('intelx')
            
            # Check LeakInsight
            leak_results = self._check_leakinsight(email)
            if leak_results:
                results['leak_databases'].extend(leak_results)
                results['sources_checked'].append('leakinsight')
            
            # Check Leak-Lookup
            lookup_results = self._check_leak_lookup(email)
            if lookup_results:
                results['leak_databases'].extend(lookup_results)
                results['sources_checked'].append('leak_lookup')
        
        if phone:
            phone_results = self._check_intelx(phone, selector_type='phonenumber')
            if phone_results:
                results['dark_web_mentions'].extend(phone_results)
        
        if name:
            name_results = self._check_intelx(f'"{name}"', selector_type='name')
            if name_results:
                results['dark_web_mentions'].extend(name_results)

        if username:
            user_results = self._check_intelx(username, selector_type='username')
            if user_results:
                results['dark_web_mentions'].extend(user_results)

        if domain:
            domain_results = self._check_intelx(domain, selector_type='domain')
            if domain_results:
                results['dark_web_mentions'].extend(domain_results)

        if ip:
            ip_results = self._check_intelx(ip, selector_type='ip')
            if ip_results:
                results['dark_web_mentions'].extend(ip_results)
        
        # Calculate exposure score
        results['exposure_score'] = self._calculate_exposure_score(results)
        
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results, email, phone)
        
        if not results['sources_checked'] and not results['dark_web_mentions']:
             # If we tried to scan but keys were missing or no hits (and we relied only on intelx for non-email)
             if not self.intelx_api_key and (name or username or domain or ip):
                 results['note'] = 'IntelX API key missing. Cannot scan Names/IPs/Domains/Usernames on Dark Web.'
             elif not self.intelx_api_key and not self.leakinsight_key and not self.leak_lookup_key:
                results['note'] = 'No API keys configured. Configure IntelX, LeakInsight, or LeakLookup API keys.'
        
        return results
    

    
    def _check_intelx(self, query: str, selector_type: str = 'email') -> List[Dict]:
        """Check IntelX for dark web mentions."""
        if not self.intelx_api_key:
            return []
        
        try:
            # Start search
            search_response = requests.post(
                'https://2.intelx.io/intelligent/search',
                headers={'x-key': self.intelx_api_key},
                json={'term': query, 'maxresults': 10, 'media': 0, 'sort': 2, 'terminate': []},
                timeout=15
            )
            
            if search_response.status_code != 200:
                return []
            
            search_id = search_response.json().get('id')
            if not search_id:
                return []
            
            # Get results
            import time
            time.sleep(2)  # Wait for results
            
            results_response = requests.get(
                f'https://2.intelx.io/intelligent/search/result?id={search_id}',
                headers={'x-key': self.intelx_api_key},
                timeout=15
            )
            
            if results_response.status_code == 200:
                data = results_response.json()
                records = data.get('records', [])
                return [{'source': 'intelx', 'name': r.get('name', 'Unknown'),
                        'type': r.get('type'), 'date': r.get('date')} for r in records[:10]]
            return []
        except Exception as e:
            logger.warning(f"IntelX check failed: {e}")
            return []
    
    def _check_leakinsight(self, email: str) -> List[Dict]:
        """Check LeakInsight for leaked credentials."""
        if not self.leakinsight_key:
            return []
        
        try:
            response = requests.get(
                f'https://leakinsight.p.rapidapi.com/email/{email}',
                headers={
                    'X-RapidAPI-Key': self.leakinsight_key,
                    'X-RapidAPI-Host': 'leakinsight.p.rapidapi.com'
                },
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('found'):
                    return [{'source': 'leakinsight', 'found': True, 'data': data}]
            return []
        except Exception as e:
            logger.warning(f"LeakInsight check failed: {e}")
            return []
    
    def _check_leak_lookup(self, email: str) -> List[Dict]:
        """Check Leak-Lookup database."""
        if not self.leak_lookup_key:
            return []
        
        try:
            response = requests.post(
                'https://leak-lookup.com/api/search',
                data={'key': self.leak_lookup_key, 'type': 'email_address', 'query': email},
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('error') != 'true' and data.get('message'):
                    return [{'source': 'leak_lookup', 'databases': data.get('message', [])}]
            return []
        except Exception as e:
            logger.warning(f"Leak-Lookup check failed: {e}")
            return []
    
    def _calculate_exposure_score(self, results: Dict) -> int:
        """Calculate dark web exposure score (0-100)."""
        score = 0
        
        # Pastes are serious (20 points each, max 40)
        score += min(len(results['pastes']) * 20, 40)
        
        # Dark web mentions (15 points each, max 30)
        score += min(len(results['dark_web_mentions']) * 15, 30)
        
        # Leak database entries (10 points each, max 30)
        score += min(len(results['leak_databases']) * 10, 30)
        
        return min(score, 100)
    
    def _generate_recommendations(self, results: Dict, email: str, phone: str) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        if results['pastes']:
            recommendations.append("Your email was found in paste sites. Change passwords for all accounts using this email immediately.")
        
        if results['dark_web_mentions']:
            recommendations.append("Your information appears on dark web sources. Enable 2FA on all accounts and monitor for suspicious activity.")
        
        if results['leak_databases']:
            recommendations.append("Your credentials may be in leaked databases. Use unique passwords for each service and consider a password manager.")
        
        if results['exposure_score'] >= 50:
            recommendations.append("HIGH RISK: Consider using a new email address for sensitive accounts.")
            recommendations.append("Set up credit monitoring and fraud alerts.")
        
        if not recommendations:
            recommendations.append("No significant dark web exposure detected. Continue practicing good security hygiene.")
        
        return recommendations

