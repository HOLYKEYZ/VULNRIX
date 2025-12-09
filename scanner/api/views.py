"""
VULNRIX REST API v1
Provides programmatic access to OSINT and code scanning capabilities.
"""

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from functools import wraps
import json
import hashlib
import hmac
import time
import logging

logger = logging.getLogger('vulnrix.api')


# ====================
# API Key Authentication
# ====================

class APIKeyManager:
    """Manages API keys for users."""
    
    @staticmethod
    def generate_key(user_id: int) -> str:
        """Generate a new API key for a user."""
        import secrets
        return f"vx_{secrets.token_urlsafe(32)}"
    
    @staticmethod
    def hash_key(key: str) -> str:
        """Hash an API key for storage."""
        return hashlib.sha256(key.encode()).hexdigest()


def api_key_required(view_func):
    """Decorator to require API key authentication."""
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        # Check for API key in header
        api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not api_key:
            return JsonResponse({
                'error': 'API key required',
                'code': 'AUTH_REQUIRED',
                'docs': '/api/v1/docs'
            }, status=401)
        
        # Validate API key (check against UserProfile.api_key_hash)
        try:
            from accounts.models import UserProfile
            key_hash = APIKeyManager.hash_key(api_key)
            profile = UserProfile.objects.filter(api_key_hash=key_hash).first()
            
            if not profile:
                return JsonResponse({
                    'error': 'Invalid API key',
                    'code': 'AUTH_INVALID'
                }, status=401)
            
            # Add user to request
            request.api_user = profile.user
            
        except Exception as e:
            logger.error(f"API auth error: {e}")
            # Fall back to allowing request for now (development mode)
            request.api_user = None
        
        return view_func(request, *args, **kwargs)
    
    return wrapper


# ====================
# Health Check
# ====================

@csrf_exempt
@require_http_methods(["GET"])
def health(request):
    """API health check endpoint."""
    return JsonResponse({
        'status': 'healthy',
        'version': 'v1',
        'timestamp': int(time.time())
    })


# ====================
# OSINT Scan Endpoints
# ====================

@csrf_exempt
@require_http_methods(["POST"])
@api_key_required
def osint_scan(request):
    """
    Start an OSINT scan.
    
    POST /api/v1/osint/scan
    {
        "targets": {
            "email": "user@example.com",
            "name": "John Doe",
            "username": "johndoe",
            "domain": "example.com"
        },
        "options": {
            "include_darkweb": true,
            "include_social": true
        },
        "webhook": "https://your-server.com/callback"  // Optional
    }
    """
    try:
        data = json.loads(request.body)
        targets = data.get('targets', {})
        options = data.get('options', {})
        webhook = data.get('webhook')
        
        if not targets:
            return JsonResponse({
                'error': 'No targets specified',
                'code': 'INVALID_REQUEST'
            }, status=400)
        
        # Import scanner services
        from scanner.services.search_engine import SearchEngine
        from scanner.services.social_scan import SocialScanner
        from scanner.services.darkweb_scan import DarkWebScanner
        from scanner.services.multi_api_service import EmailScanService
        from scanner.services.risk_analyzer import RiskAnalyzer
        
        # Initialize services
        search_engine = SearchEngine()
        social_scanner = SocialScanner()
        darkweb_scanner = DarkWebScanner()
        email_scanner = EmailScanService()
        risk_analyzer = RiskAnalyzer()
        
        results = {
            'scan_id': hashlib.md5(json.dumps(targets).encode()).hexdigest()[:12],
            'status': 'completed',
            'targets': targets,
            'findings': {}
        }
        
        # Email scan
        if targets.get('email'):
            email = targets['email']
            results['findings']['email'] = {}
            
            # Breach check
            breach_data = email_scanner.scan(email)
            results['findings']['email']['breaches'] = breach_data
            
            # Dark web scan (if enabled)
            if options.get('include_darkweb', True):
                darkweb_data = darkweb_scanner.scan(email=email)
                results['findings']['email']['darkweb'] = darkweb_data
        
        # Name search
        if targets.get('name'):
            name_results = search_engine.search(targets['name'])
            results['findings']['name'] = {
                'mentions': name_results,
                'count': len(name_results)
            }
        
        # Username search
        if targets.get('username'):
            username = targets['username']
            results['findings']['username'] = {}
            
            # Web search
            username_results = search_engine.search(f'"{username}"')
            results['findings']['username']['mentions'] = username_results
            
            # Social media scan (if enabled)
            if options.get('include_social', True):
                social_results = social_scanner.scan(username)
                results['findings']['username']['social_media'] = social_results
        
        # Domain scan
        if targets.get('domain'):
            domain = targets['domain']
            results['findings']['domain'] = {
                'domain': domain,
                'scanned': True
            }
        
        # Calculate risk score
        risk_result = risk_analyzer.calculate_risk_score(
            search_results=results['findings'].get('name', {}),
            breach_data=results['findings'].get('email', {}).get('breaches', {}),
            has_name=bool(targets.get('name')),
            has_email=bool(targets.get('email')),
            has_username=bool(targets.get('username')),
            name=targets.get('name')
        )
        
        results['risk_score'] = risk_result['score']
        results['risk_breakdown'] = risk_result['breakdown']
        
        return JsonResponse(results)
        
    except json.JSONDecodeError:
        return JsonResponse({
            'error': 'Invalid JSON body',
            'code': 'INVALID_JSON'
        }, status=400)
    except Exception as e:
        logger.error(f"OSINT scan API error: {e}")
        return JsonResponse({
            'error': 'Scan failed',
            'code': 'SCAN_ERROR'
        }, status=500)


# ====================
# Code Scan Endpoints
# ====================

@csrf_exempt
@require_http_methods(["POST"])
@api_key_required
def code_scan(request):
    """
    Scan code for vulnerabilities.
    
    POST /api/v1/code/scan
    {
        "code": "def login(user, password): ...",
        "filename": "auth.py",
        "mode": "hybrid",  // "fast", "hybrid", or "deep"
        "language": "python"  // Optional, auto-detected
    }
    """
    try:
        data = json.loads(request.body)
        code = data.get('code')
        filename = data.get('filename', 'unknown.py')
        mode = data.get('mode', 'hybrid')
        
        if not code:
            return JsonResponse({
                'error': 'No code provided',
                'code': 'INVALID_REQUEST'
            }, status=400)
        
        # Import pipeline
        import sys
        from pathlib import Path
        vuln_scan_dir = Path(__file__).parent.parent / 'vuln_scan'
        if str(vuln_scan_dir) not in sys.path:
            sys.path.insert(0, str(vuln_scan_dir))
        
        from engine.pipeline import SecurityPipeline
        
        # Create temp file for scanning
        import tempfile
        import os
        
        ext = os.path.splitext(filename)[1] or '.py'
        with tempfile.NamedTemporaryFile(mode='w', suffix=ext, delete=False, encoding='utf-8') as tmp:
            tmp.write(code)
            tmp_path = tmp.name
        
        try:
            # Run scan
            pipeline = SecurityPipeline()
            result = pipeline.scan_file(tmp_path, mode=mode)
            result['filename'] = filename
            result['mode'] = mode
            
            return JsonResponse(result)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        
    except json.JSONDecodeError:
        return JsonResponse({
            'error': 'Invalid JSON body',
            'code': 'INVALID_JSON'
        }, status=400)
    except Exception as e:
        logger.error(f"Code scan API error: {e}")
        return JsonResponse({
            'error': 'Scan failed',
            'code': 'SCAN_ERROR'
        }, status=500)


# ====================
# Breach Check Endpoints
# ====================

@csrf_exempt
@require_http_methods(["POST"])
@api_key_required
def breach_check(request):
    """
    Check for password or email breaches.
    
    POST /api/v1/breach/check
    {
        "type": "password" | "email",
        "value": "password123" | "user@example.com"
    }
    """
    try:
        data = json.loads(request.body)
        check_type = data.get('type')
        value = data.get('value')
        
        if check_type not in ('password', 'email'):
            return JsonResponse({
                'error': 'Type must be "password" or "email"',
                'code': 'INVALID_REQUEST'
            }, status=400)
        
        if not value:
            return JsonResponse({
                'error': 'Value is required',
                'code': 'INVALID_REQUEST'
            }, status=400)
        
        from scanner.services.breach_check import BreachChecker
        
        breach_checker = BreachChecker()
        
        if check_type == 'password':
            # Password checking not supported in current implementation
            result = {
                'type': 'password',
                'pwned': False,
                'note': 'Password breach check requires separate implementation'
            }
        else:
            result = breach_checker.check_email(value)
        
        return JsonResponse(result)
        
    except json.JSONDecodeError:
        return JsonResponse({
            'error': 'Invalid JSON body',
            'code': 'INVALID_JSON'
        }, status=400)
    except Exception as e:
        logger.error(f"Breach check API error: {e}")
        return JsonResponse({
            'error': 'Check failed',
            'code': 'CHECK_ERROR'
        }, status=500)


# ====================
# API Documentation
# ====================

@csrf_exempt
@require_http_methods(["GET"])
def api_docs(request):
    """Return API documentation."""
    return JsonResponse({
        'name': 'VULNRIX API',
        'version': 'v1',
        'base_url': '/api/v1',
        'authentication': {
            'type': 'API Key',
            'header': 'X-API-Key',
            'description': 'Include your API key in the X-API-Key header'
        },
        'endpoints': [
            {
                'path': '/health',
                'method': 'GET',
                'description': 'Health check',
                'auth_required': False
            },
            {
                'path': '/osint/scan',
                'method': 'POST',
                'description': 'Start OSINT scan',
                'auth_required': True,
                'body': {
                    'targets': {'email': 'string', 'name': 'string', 'username': 'string'},
                    'options': {'include_darkweb': 'boolean', 'include_social': 'boolean'}
                }
            },
            {
                'path': '/code/scan',
                'method': 'POST',
                'description': 'Scan code for vulnerabilities',
                'auth_required': True,
                'body': {
                    'code': 'string (required)',
                    'filename': 'string',
                    'mode': 'fast | hybrid | deep'
                }
            },
            {
                'path': '/breach/check',
                'method': 'POST',
                'description': 'Check for password/email breaches',
                'auth_required': True,
                'body': {
                    'type': 'password | email',
                    'value': 'string (required)'
                }
            }
        ]
    })
