"""
Fallback Metrics Views - Dashboard for API vs C fallback statistics.
"""

from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods

from scanner.services.fallback.fallback_metrics import get_metrics
from scanner.services.fallback.api_health_checker import APIHealthChecker


@login_required
@require_http_methods(["GET"])
def fallback_dashboard(request):
    """Render fallback metrics dashboard."""
    metrics = get_metrics()
    health_checker = APIHealthChecker()
    
    context = {
        'stats': metrics.get_stats(days=7),
        'api_reliability': metrics.get_api_reliability(),
        'failure_reasons': metrics.get_failure_reasons(),
        'api_health': {
            api: health_checker.check_api_status(api)
            for api in ['google_search', 'intelx', 'leakinsight', 'shodan', 'securitytrails']
        }
    }
    
    return render(request, 'fallback_dashboard.html', context)


@login_required
@require_http_methods(["GET"])
def fallback_stats_api(request):
    """API endpoint for fallback statistics."""
    metrics = get_metrics()
    days = int(request.GET.get('days', 7))
    
    return JsonResponse({
        'stats': metrics.get_stats(days=days),
        'api_reliability': metrics.get_api_reliability(),
        'failure_reasons': metrics.get_failure_reasons(),
    })


@login_required
@require_http_methods(["GET"])
def api_health_api(request):
    """API endpoint for checking API health."""
    health_checker = APIHealthChecker()
    api_name = request.GET.get('api')
    force = request.GET.get('force', 'false').lower() == 'true'
    
    if api_name:
        # Check specific API
        status = health_checker.check_api_status(api_name, force_check=force)
        return JsonResponse({api_name: status})
    
    # Check all configured APIs
    apis = [
        # OSINT Scanner APIs
        'google_search', 'intelx', 'grok', 'leakinsight', 'leak_lookup',
        'virustotal', 'shodan', 'pulsedive', 'whoisfreaks', 'securitytrails',
        'dymo', 'numlookup', 'veriphone',
        # Vulnerability Scanner APIs
        'groq', 'snyk'
    ]
    
    results = {}
    for api in apis:
        results[api] = health_checker.check_api_status(api, force_check=force)
    
    return JsonResponse(results)


@login_required
@require_http_methods(["POST"])
def clear_metrics(request):
    """Clear old metrics data."""
    metrics = get_metrics()
    days = int(request.POST.get('days', 30))
    metrics.clear_old_records(days=days)
    
    return JsonResponse({'success': True, 'message': f'Cleared records older than {days} days'})
