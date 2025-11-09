"""
API Key Manager for Digital Footprint Shield.
Manages API key rotation, rate limiting, and quota handling.
Now fetches keys dynamically from a secure GitHub Gist URL.
"""

import json
import os
import requests
from typing import Optional, Tuple
from utils.display import print_warning, print_danger, print_info


class APIKeyManager:
    """Manages API key pools with rotation and error handling."""

    def __init__(self, remote_url: str = None):
        """
        Initialize the API key manager.
        
        Args:
            remote_url: Optional GitHub Gist raw URL to load API keys from
        """
        self.remote_url = remote_url or "https://gist.githubusercontent.com/HOLYKEYZ/8342ec6149ad843313e99126707e926a/raw/2fceddaf2d53edea282bf185322b779e676c4e01/gistfile1.txt"
        self.keys_data = {}
        self.current_key_indices = {}
        self.failed_keys = {}
        self.load_remote_keys()

    def load_remote_keys(self) -> bool:
        """
        Load API keys from a remote GitHub Gist.
        
        Returns:
            True if keys loaded successfully, False otherwise
        """
        try:
            print_info(f"🌐 Fetching API keys from GitHub Gist...")
            response = requests.get(self.remote_url, timeout=10)
            response.raise_for_status()

            self.keys_data = json.loads(response.text)

            # Initialize rotation tracking
            for service in self.keys_data.keys():
                self.current_key_indices[service] = 0
                self.failed_keys[service] = set()

            print_info("✅ Loaded API keys from GitHub Gist successfully.")
            return True

        except requests.exceptions.RequestException as e:
            print_danger(f"❌ Failed to fetch keys from GitHub Gist: {str(e)}")
            return False
        except json.JSONDecodeError:
            print_danger("❌ Invalid JSON format in remote key file.")
            return False

    def get_api_key(self, service: str) -> Optional[str]:
        """Get the next available API key for a service."""
        if service not in self.keys_data:
            print_warning(f"⚠️  Service '{service}' not found in key data")
            return None

        api_keys = self.keys_data[service].get('api_keys', [])
        if not api_keys:
            print_warning(f"⚠️  No API keys configured for '{service}'")
            return None

        enabled_keys = [
            (i, k) for i, k in enumerate(api_keys)
            if k.get('enabled', True) and k.get('key', '').strip()
        ]

        if not enabled_keys:
            print_danger(f"❌ No available API keys for '{service}'")
            return None

        idx = self.current_key_indices.get(service, 0) % len(enabled_keys)
        self.current_key_indices[service] = (idx + 1) % len(enabled_keys)
        return enabled_keys[idx][1]['key']

    def mark_key_failed(self, service: str, key: str):
        """Mark an API key as failed (rate limited or quota exceeded)."""
        if service not in self.keys_data:
            return

        api_keys = self.keys_data[service].get('api_keys', [])
        for i, key_data in enumerate(api_keys):
            if key_data.get('key') == key:
                self.failed_keys.setdefault(service, set()).add(i)
                print_warning(f"⚠️  Marked key {i+1} for '{service}' as failed.")
                break

    def reset_failed_keys(self, service: str):
        """Reset failed keys for a service."""
        if service in self.failed_keys:
            self.failed_keys[service] = set()
            print_info(f"✅ Reset failed keys for '{service}'")

    def get_search_engine_id(self) -> Optional[str]:
        """Return the Google Custom Search Engine ID."""
        if 'google_custom_search' not in self.keys_data:
            return None
        return self.keys_data['google_custom_search'].get('search_engine_id')

    def get_next_key_with_retry(self, service: str, max_retries: int = None) -> Optional[str]:
        """Rotate through available API keys."""
        available = self.keys_data.get(service, {}).get('api_keys', [])
        if not available:
            print_danger(f"❌ No available keys for '{service}'")
            return None

        if max_retries is None:
            max_retries = len(available)

        tried = set()
        for _ in range(max_retries):
            key = self.get_api_key(service)
            if not key or key in tried:
                continue
            tried.add(key)
            return key

        return None


def get_api_key_for_search(api_key_manager: APIKeyManager) -> Tuple[Optional[str], Optional[str]]:
    """
    Get an API key and Search Engine ID for Google Custom Search.
    Modular function for getting API credentials.
    """
    api_key = api_key_manager.get_next_key_with_retry('google_custom_search')
    search_engine_id = api_key_manager.get_search_engine_id()
    return api_key, search_engine_id
