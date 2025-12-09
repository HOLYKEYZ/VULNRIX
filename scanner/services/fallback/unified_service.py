"""
Unified Scanner Service - Base class for API + C fallback pattern.
All scanner services should inherit from this to get automatic fallback.
"""

import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Callable
from datetime import datetime

from .api_health_checker import APIHealthChecker
from .fallback_metrics import get_metrics

logger = logging.getLogger('vulnrix.fallback.service')


class UnifiedScannerService(ABC):
    """
    Base class for scanner services with automatic API/C fallback.
    
    Subclasses must implement:
        - _api_scan(): Perform scan using API
        - _c_fallback_scan(): Perform scan using C implementation
        - api_name: Name of the primary API
    """
    
    # Override in subclass
    api_name: str = None
    fallback_api_names: list = []
    
    def __init__(self):
        self.health_checker = APIHealthChecker()
        self.metrics = get_metrics()
        self._c_module_loaded = False
        self._c_module = None
        self._load_c_module()
    
    def _load_c_module(self):
        """Attempt to load C extension module."""
        try:
            # Subclasses override this to load their specific C module
            self._c_module = self._get_c_module()
            self._c_module_loaded = self._c_module is not None
            if self._c_module_loaded:
                logger.info(f"C fallback module loaded for {self.__class__.__name__}")
        except Exception as e:
            logger.warning(f"C fallback module not available for {self.__class__.__name__}: {e}")
            self._c_module_loaded = False
    
    def _get_c_module(self) -> Optional[Any]:
        """
        Override in subclass to return the C extension module.
        Return None if no C module available.
        """
        return None
    
    def scan(self, target: Any, scan_type: str = None, **kwargs) -> Dict:
        """
        Perform scan with automatic API/C fallback.
        
        Args:
            target: The target to scan (varies by service)
            scan_type: Type of scan (for metrics)
            **kwargs: Additional arguments for the scan
            
        Returns:
            Standardized result dictionary
        """
        scan_type = scan_type or self.api_name or 'unknown'
        
        # 1. Check API health
        api_status = self.health_checker.check_api_status(self.api_name)
        
        # 2. Try API if available
        if api_status['available'] and not api_status['fallback_needed']:
            result = self._try_api_scan(target, scan_type, **kwargs)
            if result.get('success'):
                return result
            
            # API failed, try fallback APIs
            logger.warning(f"Primary API {self.api_name} failed, trying fallbacks")
        
        # 3. Try fallback APIs
        for fallback_api in api_status.get('fallback_apis', []) + self.fallback_api_names:
            fallback_status = self.health_checker.check_api_status(fallback_api)
            if fallback_status['available']:
                result = self._try_fallback_api_scan(target, fallback_api, scan_type, **kwargs)
                if result.get('success'):
                    return result
        
        # 4. Use C fallback
        if self._c_module_loaded:
            return self._try_c_fallback_scan(target, scan_type, **kwargs)
        
        # 5. All methods failed
        return self._format_result(
            data=None,
            source='none',
            success=False,
            error='All scan methods failed (API and C fallback)'
        )
    
    def _try_api_scan(self, target: Any, scan_type: str, **kwargs) -> Dict:
        """Try scanning with primary API."""
        start_time = time.time()
        try:
            result = self._api_scan(target, **kwargs)
            duration_ms = (time.time() - start_time) * 1000
            
            self.metrics.record(
                method='api',
                scan_type=scan_type,
                success=True,
                duration_ms=duration_ms,
                api_name=self.api_name
            )
            self.health_checker.record_api_usage(self.api_name)
            
            return self._format_result(result, source='api', success=True)
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(f"API scan failed: {e}")
            
            self.metrics.record(
                method='api',
                scan_type=scan_type,
                success=False,
                duration_ms=duration_ms,
                api_name=self.api_name,
                error=str(e)
            )
            self.health_checker.record_api_failure(self.api_name)
            
            return self._format_result(None, source='api', success=False, error=str(e))
    
    def _try_fallback_api_scan(self, target: Any, fallback_api: str, 
                                scan_type: str, **kwargs) -> Dict:
        """Try scanning with a fallback API."""
        start_time = time.time()
        try:
            result = self._fallback_api_scan(target, fallback_api, **kwargs)
            duration_ms = (time.time() - start_time) * 1000
            
            self.metrics.record(
                method='api',
                scan_type=scan_type,
                success=True,
                duration_ms=duration_ms,
                api_name=fallback_api
            )
            
            return self._format_result(result, source=f'api:{fallback_api}', success=True)
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.warning(f"Fallback API {fallback_api} failed: {e}")
            
            self.metrics.record(
                method='api',
                scan_type=scan_type,
                success=False,
                duration_ms=duration_ms,
                api_name=fallback_api,
                error=str(e)
            )
            
            return self._format_result(None, source=f'api:{fallback_api}', success=False, error=str(e))
    
    def _try_c_fallback_scan(self, target: Any, scan_type: str, **kwargs) -> Dict:
        """Try scanning with C fallback."""
        start_time = time.time()
        try:
            result = self._c_fallback_scan(target, **kwargs)
            duration_ms = (time.time() - start_time) * 1000
            
            self.metrics.record(
                method='c_fallback',
                scan_type=scan_type,
                success=True,
                duration_ms=duration_ms,
                api_name=self.api_name
            )
            
            return self._format_result(result, source='c_fallback', success=True)
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(f"C fallback scan failed: {e}")
            
            self.metrics.record(
                method='c_fallback',
                scan_type=scan_type,
                success=False,
                duration_ms=duration_ms,
                api_name=self.api_name,
                error=str(e)
            )
            
            return self._format_result(None, source='c_fallback', success=False, error=str(e))
    
    def _format_result(self, data: Any, source: str, success: bool = True, 
                       error: str = None) -> Dict:
        """
        Format result in standardized structure.
        Both API and C fallback return same format.
        """
        return {
            'success': success,
            'data': data,
            'source': source,
            'timestamp': datetime.now().isoformat(),
            'error': error,
            'cached': False,
        }
    
    @abstractmethod
    def _api_scan(self, target: Any, **kwargs) -> Any:
        """
        Perform scan using primary API.
        Must be implemented by subclass.
        
        Returns:
            Raw scan result data
        """
        pass
    
    def _fallback_api_scan(self, target: Any, fallback_api: str, **kwargs) -> Any:
        """
        Perform scan using fallback API.
        Override in subclass if fallback APIs are available.
        
        Returns:
            Raw scan result data
        """
        raise NotImplementedError(f"Fallback API {fallback_api} not implemented")
    
    @abstractmethod
    def _c_fallback_scan(self, target: Any, **kwargs) -> Any:
        """
        Perform scan using C implementation.
        Must be implemented by subclass.
        
        Returns:
            Raw scan result data (same format as API)
        """
        pass
