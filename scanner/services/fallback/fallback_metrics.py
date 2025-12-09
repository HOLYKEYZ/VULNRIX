"""
Fallback Metrics - Track API vs C fallback usage.
Provides statistics for monitoring and cost analysis.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from threading import Lock
from collections import defaultdict

logger = logging.getLogger('vulnrix.fallback.metrics')


class FallbackMetrics:
    """
    Track and report on API vs C fallback usage.
    Provides insights into cost savings and reliability.
    """
    
    # Estimated costs per API call (USD)
    API_COSTS = {
        'google_search': 0.005,
        'intelx': 0.01,
        'hibp': 0.0035,
        'virustotal': 0.0,  # Free tier
        'shodan': 0.0,  # Credits-based
        'securitytrails': 0.02,
        'whoisfreaks': 0.01,
        'pulsedive': 0.0,
        'numlookup': 0.005,
        'veriphone': 0.005,
    }
    
    def __init__(self):
        self._lock = Lock()
        self._records: List[Dict] = []
        self._daily_stats: Dict[str, Dict] = defaultdict(lambda: {
            'api_calls': 0,
            'c_fallback_calls': 0,
            'api_failures': 0,
            'api_time_ms': 0,
            'c_time_ms': 0,
        })
        self._start_time = datetime.now()
    
    def record(self, method: str, scan_type: str, success: bool, 
               duration_ms: float = 0, api_name: str = None, error: str = None):
        """
        Record a scan operation.
        
        Args:
            method: 'api' or 'c_fallback'
            scan_type: Type of scan performed
            success: Whether the operation succeeded
            duration_ms: Time taken in milliseconds
            api_name: Name of the API used (if method='api')
            error: Error message if failed
        """
        record = {
            'timestamp': datetime.now().isoformat(),
            'method': method,
            'scan_type': scan_type,
            'success': success,
            'duration_ms': duration_ms,
            'api_name': api_name,
            'error': error,
        }
        
        with self._lock:
            self._records.append(record)
            
            # Update daily stats
            today = datetime.now().strftime('%Y-%m-%d')
            stats = self._daily_stats[today]
            
            if method == 'api':
                stats['api_calls'] += 1
                stats['api_time_ms'] += duration_ms
                if not success:
                    stats['api_failures'] += 1
            else:
                stats['c_fallback_calls'] += 1
                stats['c_time_ms'] += duration_ms
            
            # Keep only last 10000 records
            if len(self._records) > 10000:
                self._records = self._records[-5000:]
        
        logger.debug(f"Recorded: {method} {scan_type} success={success} {duration_ms:.1f}ms")
    
    def get_stats(self, days: int = 7) -> Dict:
        """
        Get aggregated statistics.
        
        Args:
            days: Number of days to include
            
        Returns:
            {
                'api_calls': int,
                'c_fallback_calls': int,
                'api_failures': int,
                'fallback_percentage': float,
                'cost_saved': float,
                'avg_api_time_ms': float,
                'avg_c_time_ms': float,
                'by_scan_type': {...},
                'by_day': {...}
            }
        """
        cutoff = datetime.now() - timedelta(days=days)
        
        with self._lock:
            # Filter records by date
            recent_records = [
                r for r in self._records 
                if datetime.fromisoformat(r['timestamp']) > cutoff
            ]
            
            # Aggregate stats
            api_calls = sum(1 for r in recent_records if r['method'] == 'api')
            c_calls = sum(1 for r in recent_records if r['method'] == 'c_fallback')
            api_failures = sum(1 for r in recent_records if r['method'] == 'api' and not r['success'])
            
            total_calls = api_calls + c_calls
            fallback_pct = (c_calls / total_calls * 100) if total_calls > 0 else 0
            
            # Calculate cost savings
            cost_saved = 0.0
            for r in recent_records:
                if r['method'] == 'c_fallback' and r['success']:
                    api_name = r.get('api_name') or r.get('scan_type', '')
                    cost_saved += self.API_COSTS.get(api_name, 0.005)
            
            # Average times
            api_times = [r['duration_ms'] for r in recent_records if r['method'] == 'api' and r['duration_ms'] > 0]
            c_times = [r['duration_ms'] for r in recent_records if r['method'] == 'c_fallback' and r['duration_ms'] > 0]
            
            avg_api_time = sum(api_times) / len(api_times) if api_times else 0
            avg_c_time = sum(c_times) / len(c_times) if c_times else 0
            
            # By scan type
            by_scan_type = defaultdict(lambda: {'api': 0, 'c_fallback': 0, 'failures': 0})
            for r in recent_records:
                st = r['scan_type']
                by_scan_type[st][r['method']] += 1
                if not r['success']:
                    by_scan_type[st]['failures'] += 1
            
            # By day
            by_day = {}
            for date_str, stats in self._daily_stats.items():
                if datetime.strptime(date_str, '%Y-%m-%d') > cutoff:
                    by_day[date_str] = dict(stats)
            
            return {
                'api_calls': api_calls,
                'c_fallback_calls': c_calls,
                'api_failures': api_failures,
                'fallback_percentage': round(fallback_pct, 2),
                'cost_saved': round(cost_saved, 2),
                'avg_api_time_ms': round(avg_api_time, 2),
                'avg_c_time_ms': round(avg_c_time, 2),
                'speedup_factor': round(avg_api_time / avg_c_time, 2) if avg_c_time > 0 else 0,
                'by_scan_type': dict(by_scan_type),
                'by_day': by_day,
                'total_records': len(self._records),
                'tracking_since': self._start_time.isoformat(),
            }
    
    def get_api_reliability(self) -> Dict[str, float]:
        """
        Get reliability percentage for each API.
        
        Returns:
            {'api_name': reliability_percentage, ...}
        """
        with self._lock:
            api_stats = defaultdict(lambda: {'success': 0, 'total': 0})
            
            for r in self._records:
                if r['method'] == 'api' and r.get('api_name'):
                    api_stats[r['api_name']]['total'] += 1
                    if r['success']:
                        api_stats[r['api_name']]['success'] += 1
            
            return {
                api: round(stats['success'] / stats['total'] * 100, 2) if stats['total'] > 0 else 100
                for api, stats in api_stats.items()
            }
    
    def get_failure_reasons(self) -> Dict[str, int]:
        """Get count of failures by reason."""
        with self._lock:
            reasons = defaultdict(int)
            for r in self._records:
                if not r['success'] and r.get('error'):
                    reasons[r['error']] += 1
            return dict(reasons)
    
    def clear_old_records(self, days: int = 30):
        """Clear records older than specified days."""
        cutoff = datetime.now() - timedelta(days=days)
        
        with self._lock:
            self._records = [
                r for r in self._records
                if datetime.fromisoformat(r['timestamp']) > cutoff
            ]
            
            # Clear old daily stats
            cutoff_str = cutoff.strftime('%Y-%m-%d')
            self._daily_stats = {
                k: v for k, v in self._daily_stats.items()
                if k >= cutoff_str
            }


# Global metrics instance
_metrics_instance = None

def get_metrics() -> FallbackMetrics:
    """Get global metrics instance."""
    global _metrics_instance
    if _metrics_instance is None:
        _metrics_instance = FallbackMetrics()
    return _metrics_instance
