"""
Configuration helper for Django - provides same interface as Flask Config.
This allows services to work with both Flask and Django.
Loads API keys from environment with proper fallback logic.
"""
import os
from django.conf import settings
from dotenv import load_dotenv

# Load .env file
load_dotenv()


class DjangoConfig:
    """Django configuration wrapper - reads from settings or env."""
    
    def _get(self, key):
        """Get config value from Django settings or environment."""
        return getattr(settings, key, None) or os.getenv(key)
    
    def _get_with_fallback(self, *keys):
        """Try multiple keys and return first valid value."""
        for key in keys:
            value = self._get(key)
            if value and value.strip():
                return value.strip()
        return None
    
    def has_key(self, key):
        """Check if an API key is configured and valid."""
        value = self._get(key)
        return bool(value and value.strip())
    
    # ===== OSINT Scanner API Keys =====
    @property
    def INTELX_API_KEY(self):
        return self._get('INTELX_API_KEY')
    
    @property
    def GOOGLE_API_KEY(self):
        return self._get('GOOGLE_API_KEY')
    
    @property
    def CSE_ID(self):
        return self._get('CSE_ID')
    
    @property
    def GROK_API_KEY(self):
        return self._get('GROK_API_KEY')
    
    @property
    def LEAKINSIGHT_API_KEY(self):
        return self._get('LEAKINSIGHT_API_KEY')
    
    @property
    def LEAK_LOOKUP_API_KEY(self):
        return self._get('LEAK_LOOKUP_API_KEY')
    
    @property
    def VIRUS_TOTAL_API_KEY(self):
        return self._get('VIRUS_TOTAL_API_KEY')
    
    @property
    def SHODAN_API_KEY(self):
        return self._get_with_fallback('SHODAN_API_KEY', 'SHODAN_API_KEY_2')
    
    @property
    def SHODAN_API_KEY_2(self):
        return self._get('SHODAN_API_KEY_2')
    
    @property
    def PULSE_DIVE_API_KEY(self):
        return self._get('PULSE_DIVE_API_KEY')
    
    @property
    def WHO_IS_FREAKS_API_KEY(self):
        return self._get('WHO_IS_FREAKS_API_KEY')
    
    @property
    def SECURITY_TRAILS_API_KEY(self):
        return self._get('SECURITY_TRAILS_API_KEY')
    
    @property
    def DYMO_API_KEY(self):
        return self._get('DYMO_API_KEY')
    
    @property
    def NUMLOOKUP_API_KEY(self):
        return self._get('NUMLOOKUP_API_KEY')
    
    @property
    def VERIPHONE_API_KEY(self):
        return self._get('VERIPHONE_API_KEY')
    
    # ===== Vulnerability Scanner API Keys =====
    @property
    def GROQ_KEY(self):
        return self._get('GROQ_KEY')
    
    @property
    def SNYK_API_KEY(self):
        return self._get('SNYK_API_KEY')
    
    # ===== API Status Methods =====
    def get_all_api_status(self):
        """Get status of all configured APIs."""
        apis = {
            'google_search': bool(self.GOOGLE_API_KEY and self.CSE_ID),
            'intelx': bool(self.INTELX_API_KEY),
            'leakinsight': bool(self.LEAKINSIGHT_API_KEY),
            'leak_lookup': bool(self.LEAK_LOOKUP_API_KEY),
            'virustotal': bool(self.VIRUS_TOTAL_API_KEY),
            'shodan': bool(self.SHODAN_API_KEY),
            'pulsedive': bool(self.PULSE_DIVE_API_KEY),
            'whoisfreaks': bool(self.WHO_IS_FREAKS_API_KEY),
            'securitytrails': bool(self.SECURITY_TRAILS_API_KEY),
            'numlookup': bool(self.NUMLOOKUP_API_KEY),
            'veriphone': bool(self.VERIPHONE_API_KEY),
            'groq': bool(self.GROQ_KEY),
            'snyk': bool(self.SNYK_API_KEY),
        }
        return apis
    
    def get_available_apis(self):
        """Get list of APIs that have valid keys configured."""
        return [name for name, available in self.get_all_api_status().items() if available]


# Create singleton instance
Config = DjangoConfig()

