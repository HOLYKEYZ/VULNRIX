"""
API Key Manager for Digital Footprint Shield.
Manages API key rotation, rate limiting, and quota handling.
Uses environment variables for API key configuration.
"""

import os
from typing import Optional, Tuple
from dotenv import load_dotenv
from utils.display import print_warning, print_danger, print_info

# Load environment variables from .env file (for local development)
load_dotenv()


class ConfigurationError(Exception):
    """Raised when required environment variables are missing."""
    pass


class APIKeyManager:
    """Manages API key pools with rotation and error handling."""

    def __init__(self):
        """
        Initialize the API key manager.
        Loads API keys from environment variables.
        """
        self.keys_data = {}
        self.current_key_indices = {}  # Track current key index for each service
        self.failed_keys = {}  # Track failed keys (rate limited, quota exceeded)
        self.load_keys_from_env()

    def load_keys_from_env(self) -> bool:
        """
        Load API keys from environment variables.
        
        Returns:
            True if keys loaded successfully, False otherwise
        """
        try:
            # Load Google Custom Search API key and CSE ID
            google_api_key = os.getenv('GOOGLE_API_KEY')
            cse_id = os.getenv('CSE_ID')
            
            if not google_api_key:
                raise ConfigurationError(
                    "GOOGLE_API_KEY environment variable is required. "
                    "Please set it in your environment or Render dashboard."
                )
            
            if not cse_id:
                raise ConfigurationError(
                    "CSE_ID environment variable is required. "
                    "Please set it in your environment or Render dashboard."
                )
            
            # Build keys data structure
            self.keys_data = {
                'google_custom_search': {
                    'api_keys': [
                        {
                            'key': google_api_key,
                            'enabled': True,
                            'description': 'Google Custom Search API key from environment'
                        }
                    ],
                    'search_engine_id': cse_id
                },
                'hibp': {
                    'api_keys': []
                },
                'grok': {
                    'api_keys': []
                }
            }
            
            # Load optional HIBP API key
            hibp_api_key = os.getenv('HIBP_API_KEY')
            if hibp_api_key:
                self.keys_data['hibp']['api_keys'] = [
                    {
                        'key': hibp_api_key,
                        'enabled': True,
                        'description': 'HIBP API key from environment'
                    }
                ]
            
            # Load optional Grok API key
            grok_api_key = os.getenv('GROK_API_KEY')
            if grok_api_key:
                self.keys_data['grok']['api_keys'] = [
                    {
                        'key': grok_api_key,
                        'enabled': True,
                        'description': 'Grok API key from environment'
                    }
                ]
            
            # Initialize current key indices for each service
            for service in self.keys_data.keys():
                self.current_key_indices[service] = 0
                self.failed_keys[service] = set()
            
            print_info("✅ Loaded API keys from environment variables")
            return True

        except ConfigurationError as e:
            print_danger(f"❌ Configuration Error: {str(e)}")
            raise
        except Exception as e:
            print_danger(f"❌ Error loading API keys: {str(e)}")
            return False

    def get_api_key(self, service: str) -> Optional[str]:
        """
        Get the next available API key for a service.
        
        Args:
            service: Service name (e.g., 'google_custom_search', 'hibp', 'grok')
        
        Returns:
            API key string, or None if no keys available
        """
        if service not in self.keys_data:
            print_warning(f"⚠️  Service '{service}' not found")
            return None
        
        service_data = self.keys_data[service]
        api_keys = service_data.get('api_keys', [])
        
        if not api_keys:
            print_warning(f"⚠️  No API keys configured for service '{service}'")
            return None
        
        # Find next available key
        enabled_keys = [
            (i, key_data) for i, key_data in enumerate(api_keys)
            if key_data.get('enabled', True) and 
               key_data.get('key', '').strip() and
               i not in self.failed_keys.get(service, set())
        ]
        
        if not enabled_keys:
            # All keys exhausted, reset failed keys and try again
            if self.failed_keys.get(service):
                print_warning(f"⚠️  All keys for '{service}' exhausted. Resetting failed keys...")
                self.failed_keys[service] = set()
                enabled_keys = [
                    (i, key_data) for i, key_data in enumerate(api_keys)
                    if key_data.get('enabled', True) and 
                       key_data.get('key', '').strip()
                ]
        
        if not enabled_keys:
            print_danger(f"❌ No available API keys for service '{service}'")
            return None
        
        # Get current index or start from 0
        current_idx = self.current_key_indices.get(service, 0)
        
        # Find next available key starting from current index
        for i in range(len(enabled_keys)):
            idx = (current_idx + i) % len(enabled_keys)
            key_index, key_data = enabled_keys[idx]
            
            # Return this key and update index
            self.current_key_indices[service] = (idx + 1) % len(enabled_keys)
            return key_data.get('key')
        
        return None

    def mark_key_failed(self, service: str, key: str):
        """
        Mark an API key as failed (rate limited or quota exceeded).
        
        Args:
            service: Service name
            key: The API key that failed
        """
        if service not in self.keys_data:
            return
        
        api_keys = self.keys_data[service].get('api_keys', [])
        for i, key_data in enumerate(api_keys):
            if key_data.get('key') == key:
                self.failed_keys.setdefault(service, set()).add(i)
                print_warning(f"⚠️  Marked key {i+1} for '{service}' as failed (rate limited/quota exceeded)")
                break

    def reset_failed_keys(self, service: str):
        """
        Reset failed keys for a service (useful after some time).
        
        Args:
            service: Service name
        """
        if service in self.failed_keys:
            self.failed_keys[service] = set()
            print_info(f"✅ Reset failed keys for '{service}'")

    def get_search_engine_id(self) -> Optional[str]:
        """
        Get the Google Custom Search Engine ID.
        
        Returns:
            Search Engine ID string, or None if not configured
        """
        if 'google_custom_search' not in self.keys_data:
            return None
        
        return self.keys_data['google_custom_search'].get('search_engine_id')

    def get_available_key_count(self, service: str) -> int:
        """
        Get the number of available API keys for a service.
        
        Args:
            service: Service name
        
        Returns:
            Number of available keys
        """
        if service not in self.keys_data:
            return 0
        
        api_keys = self.keys_data[service].get('api_keys', [])
        enabled_keys = [
            key_data for key_data in api_keys
            if key_data.get('enabled', True) and 
               key_data.get('key', '').strip()
        ]
        
        return len(enabled_keys)

    def get_next_key_with_retry(self, service: str, max_retries: int = None) -> Optional[str]:
        """
        Get the next API key, automatically rotating through the pool.
        This is the main function to use for getting an API key.
        
        Args:
            service: Service name
            max_retries: Maximum number of keys to try (None = try all)
        
        Returns:
            API key string, or None if all keys exhausted
        """
        if max_retries is None:
            max_retries = self.get_available_key_count(service)
        
        tried_keys = set()
        for _ in range(max_retries):
            key = self.get_api_key(service)
            if key is None:
                break
            
            # Avoid infinite loop if we've tried all keys
            if key in tried_keys:
                break
            
            tried_keys.add(key)
            return key
        
        return None


def get_api_key_for_search(api_key_manager: APIKeyManager) -> Tuple[Optional[str], Optional[str]]:
    """
    Get an API key and Search Engine ID for Google Custom Search.
    Modular function for getting API credentials.
    
    Args:
        api_key_manager: APIKeyManager instance
    
    Returns:
        Tuple of (api_key, search_engine_id)
    """
    api_key = api_key_manager.get_next_key_with_retry('google_custom_search')
    search_engine_id = api_key_manager.get_search_engine_id()
    
    return api_key, search_engine_id
