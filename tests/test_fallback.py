"""
Tests for C Fallback System
"""

import unittest
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAPIHealthChecker(unittest.TestCase):
    """Test API health checking functionality."""
    
    def setUp(self):
        from scanner.services.fallback.api_health_checker import APIHealthChecker
        self.checker = APIHealthChecker()
    
    def test_check_unknown_api(self):
        """Unknown API should return fallback needed."""
        status = self.checker.check_api_status('unknown_api_xyz')
        self.assertFalse(status['available'])
        self.assertEqual(status['reason'], 'unknown_api')
        self.assertTrue(status['fallback_needed'])
    
    def test_check_api_no_key(self):
        """API without key should return fallback needed."""
        # Temporarily unset key
        old_key = os.environ.get('SHODAN_API_KEY')
        if 'SHODAN_API_KEY' in os.environ:
            del os.environ['SHODAN_API_KEY']
        
        status = self.checker.check_api_status('shodan', force_check=True)
        self.assertFalse(status['available'])
        self.assertTrue(status['fallback_needed'])
        
        # Restore key
        if old_key:
            os.environ['SHODAN_API_KEY'] = old_key
    
    def test_cache_works(self):
        """Health check results should be cached."""
        # First check
        status1 = self.checker.check_api_status('google_search')
        # Second check should use cache
        status2 = self.checker.check_api_status('google_search')
        
        self.assertEqual(status1['checked_at'], status2['checked_at'])
    
    def test_force_check_bypasses_cache(self):
        """Force check should bypass cache."""
        status1 = self.checker.check_api_status('google_search')
        status2 = self.checker.check_api_status('google_search', force_check=True)
        
        # Timestamps should be different
        self.assertNotEqual(status1['checked_at'], status2['checked_at'])


class TestFallbackMetrics(unittest.TestCase):
    """Test fallback metrics tracking."""
    
    def setUp(self):
        from scanner.services.fallback.fallback_metrics import FallbackMetrics
        self.metrics = FallbackMetrics()
    
    def test_record_api_call(self):
        """Should record API calls."""
        self.metrics.record('api', 'test_scan', True, 100.0, 'test_api')
        stats = self.metrics.get_stats(days=1)
        
        self.assertGreaterEqual(stats['api_calls'], 1)
    
    def test_record_c_fallback(self):
        """Should record C fallback calls."""
        self.metrics.record('c_fallback', 'test_scan', True, 50.0, 'test_api')
        stats = self.metrics.get_stats(days=1)
        
        self.assertGreaterEqual(stats['c_fallback_calls'], 1)
    
    def test_cost_savings(self):
        """Should calculate cost savings."""
        # Record some C fallback calls
        for _ in range(10):
            self.metrics.record('c_fallback', 'google_search', True, 50.0, 'google_search')
        
        stats = self.metrics.get_stats(days=1)
        self.assertGreater(stats['cost_saved'], 0)


class TestDNSFallback(unittest.TestCase):
    """Test DNS fallback module."""
    
    def setUp(self):
        from c_fallback_modules.dns_scanner import DNSFallback
        self.dns = DNSFallback(timeout=2.0)
    
    def test_get_dns_records(self):
        """Should get DNS records for a domain."""
        result = self.dns.get_dns_records('google.com')
        
        self.assertEqual(result['domain'], 'google.com')
        self.assertIn('records', result)
        self.assertEqual(result['method'], 'dns_query')
    
    def test_enumerate_subdomains(self):
        """Should enumerate subdomains."""
        result = self.dns.enumerate_subdomains('google.com', max_results=5)
        
        self.assertEqual(result['domain'], 'google.com')
        self.assertIn('subdomains', result)
        self.assertEqual(result['method'], 'dns_bruteforce')
    
    def test_reverse_dns(self):
        """Should perform reverse DNS lookup."""
        hostname = self.dns.reverse_dns('8.8.8.8')
        # Google's DNS should resolve
        self.assertIsNotNone(hostname)


class TestPortScanner(unittest.TestCase):
    """Test port scanner fallback module."""
    
    def setUp(self):
        from c_fallback_modules.network_scanner import PortScanner
        self.scanner = PortScanner(timeout=1.0)
    
    def test_scan_localhost(self):
        """Should scan localhost."""
        result = self.scanner.scan('127.0.0.1', ports=[80, 443], scan_type='quick')
        
        self.assertEqual(result['target'], '127.0.0.1')
        self.assertIn('ports', result)
        self.assertEqual(result['method'], 'tcp_connect')
    
    def test_scan_invalid_host(self):
        """Should handle invalid host gracefully."""
        result = self.scanner.scan('invalid.host.that.does.not.exist.xyz')
        
        self.assertIn('error', result)


class TestBreachFallback(unittest.TestCase):
    """Test breach checker fallback module."""
    
    def setUp(self):
        from c_fallback_modules.breach_checker import BreachFallback
        self.breach = BreachFallback()
    
    def test_check_email(self):
        """Should check email for breaches."""
        result = self.breach.check_email('test@example.com')
        
        self.assertIn('email', result)
        self.assertIn('breached', result)
        self.assertIn('method', result)
    
    def test_check_invalid_email(self):
        """Should handle invalid email."""
        result = self.breach.check_email('not-an-email')
        
        self.assertFalse(result['breached'])
        self.assertIn('error', result)
    
    def test_check_password(self):
        """Should check password exposure."""
        # Use a known breached password
        result = self.breach.check_password('password123')
        
        self.assertIn('exposed', result)
        self.assertIn('method', result)
    
    def test_hash_email(self):
        """Should generate email hashes."""
        result = self.breach.hash_email('test@example.com')
        
        self.assertIn('sha1', result)
        self.assertIn('sha256', result)
        self.assertIn('md5', result)


class TestUnifiedService(unittest.TestCase):
    """Test unified service pattern."""
    
    def test_intelx_service_v2(self):
        """IntelX service should work with fallback."""
        from scanner.services.intelx_service_v2 import IntelXServiceV2
        
        service = IntelXServiceV2()
        
        # Should not raise even without API key
        result = service.search_email('test@example.com')
        
        self.assertIn('success', result)
        self.assertIn('source', result)
        self.assertIn('data', result)


if __name__ == '__main__':
    unittest.main()
