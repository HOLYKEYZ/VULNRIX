"""
HaveIBeenPwned API integration for checking email breaches.
"""

import requests
import hashlib
from typing import List, Dict, Optional
from utils.display import print_warning, print_danger, print_info


class BreachChecker:
    """Handles HaveIBeenPwned API queries for breach checking."""
    
    def __init__(self):
        """Initialize the breach checker."""
        self.api_base_url = "https://haveibeenpwned.com/api/v3"
        self.breach_endpoint = f"{self.api_base_url}/breachedaccount"
        self.paste_endpoint = f"{self.api_base_url}/pasteaccount"
    
    def check_email(self, email: str, api_key: Optional[str] = None) -> Dict:
        """
        Check if an email has been involved in data breaches.
        
        Args:
            email: Email address to check
            api_key: Optional HIBP API key (for higher rate limits)
        
        Returns:
            Dictionary with 'breaches' and 'pastes' lists, and 'total_breaches' count
        """
        if not email or '@' not in email:
            return {'breaches': [], 'pastes': [], 'total_breaches': 0}
        
        result = {
            'breaches': [],
            'pastes': [],
            'total_breaches': 0
        }
        
        headers = {}
        if api_key:
            headers['hibp-api-key'] = api_key
        
        # Check for breaches
        try:
            print_info(f"🔍 Checking breaches for: {email}")
            breach_url = f"{self.breach_endpoint}/{email}"
            response = requests.get(breach_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                breaches = response.json()
                result['breaches'] = breaches
                result['total_breaches'] = len(breaches)
            elif response.status_code == 404:
                # Email not found in breaches - this is good!
                result['breaches'] = []
                result['total_breaches'] = 0
            else:
                print_warning(f"⚠️  API returned status {response.status_code}")
        
        except requests.exceptions.RequestException as e:
            print_danger(f"❌ Error checking breaches: {str(e)}")
            # If rate limited, suggest using API key
            if "429" in str(e) or "rate limit" in str(e).lower():
                print_warning("💡 Tip: Use a HIBP API key for higher rate limits")
        
        # Check for pastes (exposed in paste sites)
        try:
            print_info(f"🔍 Checking pastes for: {email}")
            paste_url = f"{self.paste_endpoint}/{email}"
            response = requests.get(paste_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                result['pastes'] = response.json()
            elif response.status_code == 404:
                result['pastes'] = []
            else:
                print_warning(f"⚠️  Paste check returned status {response.status_code}")
        
        except requests.exceptions.RequestException as e:
            print_danger(f"❌ Error checking pastes: {str(e)}")
        
        return result
    
    def format_breach_info(self, breach_data: Dict) -> List[str]:
        """
        Format breach information for display.
        
        Args:
            breach_data: Dictionary containing breach information
        
        Returns:
            List of formatted strings describing breaches
        """
        formatted = []
        
        if breach_data['total_breaches'] > 0:
            formatted.append(f"Found {breach_data['total_breaches']} data breach(es):")
            for breach in breach_data['breaches']:
                breach_name = breach.get('Name', 'Unknown')
                breach_date = breach.get('BreachDate', 'Unknown')
                breach_domain = breach.get('Domain', 'Unknown')
                formatted.append(f"  • {breach_name} ({breach_domain}) - Breached: {breach_date}")
        else:
            formatted.append("No known data breaches found.")
        
        if breach_data['pastes']:
            formatted.append(f"Found {len(breach_data['pastes'])} paste(s) containing this email:")
            for paste in breach_data['pastes']:
                paste_source = paste.get('Source', 'Unknown')
                paste_id = paste.get('Id', 'Unknown')
                formatted.append(f"  • {paste_source} (ID: {paste_id})")
        else:
            formatted.append("No pastes found.")
        
        return formatted

