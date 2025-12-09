"""
Django views for scanner app - converted from Flask routes.
"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from .models import ScanHistory, ScanResult

# Import services (works with both Django and Flask)
from scanner.services.intelx_service import IntelXService
from scanner.services.search_engine import SearchEngine
from scanner.services.social_scan import SocialScanner
from scanner.services.phone_scan import PhoneScanner
from scanner.services.ip_scan import IPScanner
from scanner.services.public_records import PublicRecordsScanner
from scanner.services.email_pattern import EmailPatternAnalyzer
from scanner.services.darkweb_scan import DarkWebScanner
from scanner.services.correlation import CorrelationAnalyzer
from scanner.services.risk_analyzer import RiskAnalyzer
from scanner.services.breach_check import BreachChecker


@login_required
@require_http_methods(["GET", "POST"])
def new_scan(request):
    """Create a new scan - mirrors Flask new_scan route."""
    if request.method == 'POST':
        # Check if this is a Quick Lookup scan
        scan_mode = request.POST.get('scan_mode', 'comprehensive')
        
        if scan_mode == 'quick':
            # Quick scan: only one field
            quick_type = request.POST.get('quick_type', '')
            quick_value = request.POST.get('quick_value', '').strip()
            
            if not quick_type or not quick_value:
                messages.error(request, 'Please select a scan type and enter a value.')
                return render(request, 'scan_form.html')
            
            # Map quick type to form field
            name = quick_value if quick_type == 'name' else None
            email = quick_value if quick_type == 'email' else None
            username = quick_value if quick_type == 'username' else None
            phone = quick_value if quick_type == 'phone' else None
            domain = quick_value if quick_type == 'domain' else None
            ip = quick_value if quick_type == 'ip' else None
            social_platforms = []
        else:
            # Comprehensive scan: get all form data
            name = request.POST.get('name', '').strip() or None
            email = request.POST.get('email', '').strip() or None
            username = request.POST.get('username', '').strip() or None
            phone = request.POST.get('phone', '').strip() or None
            domain = request.POST.get('domain', '').strip() or None
            ip = request.POST.get('ip', '').strip() or None
            social_platforms = request.POST.getlist('social_platforms')
        
        # Validate at least one field
        if not any([name, email, username, phone, domain, ip]):
            messages.error(request, 'Please provide at least one field to scan.')
            return render(request, 'scan_form.html')
        
        # Create scan record
        scan = ScanHistory(
            user=request.user,
            name=name,
            email=email,
            username=username,
            phone=phone,
            domain=domain,
            ip=ip,
            social_handles=social_platforms
        )
        scan.save()
        
        # Initialize scanners
        intelx_service = IntelXService()
        search_engine = SearchEngine()
        social_scanner = SocialScanner(search_engine)
        phone_scanner = PhoneScanner(search_engine)
        ip_scanner = IPScanner()
        public_records_scanner = PublicRecordsScanner(search_engine)
        email_pattern_analyzer = EmailPatternAnalyzer(search_engine)
        darkweb_scanner = DarkWebScanner()
        correlation_analyzer = CorrelationAnalyzer()
        breach_checker = BreachChecker()
        risk_analyzer = RiskAnalyzer()
        
        # Run scans
        try:
            # IntelX OSINT scans (primary method)
            intelx_results = {
                'email': {},
                'username': {},
                'phone': {},
                'domain': {},
                'name': {}
            }
            
            if email:
                intelx_results['email'] = intelx_service.search_email(email)
            if username:
                intelx_results['username'] = intelx_service.search_username(username)
            if phone:
                intelx_results['phone'] = intelx_service.search_phone(phone)
            if domain:
                intelx_results['domain'] = intelx_service.search_domain(domain)
            if name:
                intelx_results['name'] = intelx_service.search_name(name)
            
            # Web search (fallback/supplementary)
            search_results = search_engine.find_mentions(
                name=name, email=email, username=username
            )
            
            # Breach check
            breach_data = breach_checker.check_email(email) if email else {'breaches': [], 'pastes': [], 'total_breaches': 0}
            
            # Social media scan
            social_results = {}
            if username and social_platforms:
                social_results = social_scanner.scan_all(username, social_platforms)
            
            # Phone scan
            phone_results = phone_scanner.scan(phone) if phone else {}
            
            # IP scan
            ip_results = ip_scanner.scan(ip) if ip else {}
            
            # Public records
            public_records = public_records_scanner.scan(name, email, phone) if name else {}
            
            # Email pattern analysis
            email_pattern = email_pattern_analyzer.analyze(email) if email else {}
            
            # Dark web scan
            darkweb_data = darkweb_scanner.scan(email, phone)
            
            # Correlation analysis
            correlation_data = correlation_analyzer.analyze(
                name=name, email=email, username=username, phone=phone,
                search_results=search_results, social_results=social_results
            )
            
            # Risk analysis
            risk_result = risk_analyzer.calculate_risk_score(
                search_results=search_results,
                breach_data=breach_data,
                has_name=bool(name),
                has_email=bool(email),
                has_username=bool(username),
                name=name,
                social_results=social_results,
                public_records=public_records,
                darkweb_data=darkweb_data,
                correlation_data=correlation_data
            )
            
            # Update scan with risk score
            scan.risk_score = risk_result['score']
            scan.save()
            
            # Create scan result
            scan_result = ScanResult(scan=scan)
            scan_result.set_json_field('search_results', search_results)
            scan_result.set_json_field('intelx_results', intelx_results)
            scan_result.set_json_field('breach_data', breach_data)
            scan_result.set_json_field('social_results', social_results)
            scan_result.set_json_field('phone_results', phone_results)
            scan_result.set_json_field('ip_results', ip_results)
            scan_result.set_json_field('public_records', public_records)
            scan_result.set_json_field('email_pattern', email_pattern)
            scan_result.set_json_field('darkweb_scan', darkweb_data)
            scan_result.set_json_field('correlation', correlation_data)
            scan_result.set_json_field('risk_breakdown', risk_result['breakdown'])
            scan_result.save()
            
            return redirect('scanner:view_scan', scan_id=scan.id)
        
        except Exception as e:
            messages.error(request, f'Error during scan: {str(e)}')
            return render(request, 'scan_form.html')
    
    return render(request, 'scan_form.html')


@login_required
def view_scan(request, scan_id):
    """View scan results - mirrors Flask view_scan route."""
    scan = get_object_or_404(ScanHistory, id=scan_id)
    
    # Verify ownership
    if scan.user != request.user:
        messages.error(request, 'You do not have permission to view this scan.')
        return redirect('scanner:dashboard')
    
    # Get results
    try:
        scan_result = scan.results
    except ScanResult.DoesNotExist:
        messages.error(request, 'Scan results not found.')
        return redirect('scanner:dashboard')
    
    # Parse JSON fields
    search_results = scan_result.get_json_field('search_results')
    intelx_results = scan_result.get_json_field('intelx_results')
    breach_data = scan_result.get_json_field('breach_data')
    social_results = scan_result.get_json_field('social_results')
    phone_results = scan_result.get_json_field('phone_results')
    ip_results = scan_result.get_json_field('ip_results')
    public_records = scan_result.get_json_field('public_records')
    email_pattern = scan_result.get_json_field('email_pattern')
    darkweb_data = scan_result.get_json_field('darkweb_scan')
    correlation_data = scan_result.get_json_field('correlation')
    risk_breakdown = scan_result.get_json_field('risk_breakdown')
    
    return render(
        request,
        'scan_result.html',
        {
            'scan': scan,
            'search_results': search_results,
            'intelx_results': intelx_results,
            'breach_data': breach_data,
            'social_results': social_results,
            'phone_results': phone_results,
            'ip_results': ip_results,
            'public_records': public_records,
            'email_pattern': email_pattern,
            'darkweb_data': darkweb_data,
            'correlation_data': correlation_data,
            'risk_breakdown': risk_breakdown
        }
    )


@login_required
def dashboard(request):
    """Dashboard view - mirrors Flask dashboard."""
    from django.db.models import Count, Q
    from datetime import datetime, timedelta
    
    # Get recent scans
    recent_scans = ScanHistory.objects.filter(user=request.user).order_by('-created_at')[:10]
    
    # Get total scans
    total_scans = ScanHistory.objects.filter(user=request.user).count()
    
    # Risk distribution
    risk_distribution = {
        'low': ScanHistory.objects.filter(user=request.user, risk_score__lt=30).count(),
        'medium': ScanHistory.objects.filter(user=request.user, risk_score__gte=30, risk_score__lt=70).count(),
        'high': ScanHistory.objects.filter(user=request.user, risk_score__gte=70).count(),
    }
    
    # Exposure trends (last 30 days + today)
    thirty_days_ago = datetime.now() - timedelta(days=30)
    exposure_trends = []
    for i in range(31):  # 31 to include today
        date = thirty_days_ago + timedelta(days=i)
        count = ScanHistory.objects.filter(
            user=request.user,
            created_at__date=date.date()
        ).count()
        exposure_trends.append({
            'date': date.strftime('%Y-%m-%d'),
            'count': count
        })
    
    import json
    return render(request, 'dashboard.html', {
        'recent_scans': recent_scans,
        'total_scans': total_scans,
        'risk_distribution': risk_distribution,
        'exposure_trends': json.dumps(exposure_trends)
    })


@login_required
@require_http_methods(["GET"])
def dashboard_stats_api(request):
    """API endpoint for live dashboard stats updates."""
    from datetime import datetime, timedelta
    
    # Get total scans
    total_scans = ScanHistory.objects.filter(user=request.user).count()
    
    # Risk distribution
    risk_distribution = {
        'low': ScanHistory.objects.filter(user=request.user, risk_score__lt=30).count(),
        'medium': ScanHistory.objects.filter(user=request.user, risk_score__gte=30, risk_score__lt=70).count(),
        'high': ScanHistory.objects.filter(user=request.user, risk_score__gte=70).count(),
    }
    
    # Exposure trends (last 7 days + today)
    seven_days_ago = datetime.now() - timedelta(days=7)
    exposure_trends = []
    for i in range(8):  # 8 to include today (days 0-7)
        date = seven_days_ago + timedelta(days=i)
        count = ScanHistory.objects.filter(
            user=request.user,
            created_at__date=date.date()
        ).count()
        exposure_trends.append({
            'date': date.strftime('%Y-%m-%d'),
            'label': date.strftime('%m/%d'),
            'count': count
        })
    
    return JsonResponse({
        'total_scans': total_scans,
        'risk_distribution': risk_distribution,
        'exposure_trends': exposure_trends
    })


@login_required
def docs(request):
    """Documentation page explaining the platform."""
    return render(request, 'docs.html')


@login_required
def attack_surface(request, scan_id):
    """Attack Surface Visualization view."""
    from scanner.services.attack_surface import build_attack_surface
    
    scan = get_object_or_404(ScanHistory, id=scan_id)
    
    # Verify ownership
    if scan.user != request.user:
        messages.error(request, 'Permission denied.')
        return redirect('scanner:dashboard')
    
    # Get results
    try:
        scan_result = scan.results
        osint_results = {
            'email': scan.email,
            'name': scan.name,
            'username': scan.username,
            'domain': scan.domain,
            'breach_data': scan_result.get_json_field('breach_data'),
            'social_results': scan_result.get_json_field('social_results'),
        }
        # Assuming code results might be linked or relevant in future
        code_results = None 
        
        graph_data = build_attack_surface(osint_results, code_results)
        
    except ScanResult.DoesNotExist:
        messages.error(request, 'Scan results not found.')
        return redirect('scanner:dashboard')
        
    return render(request, 'attack_surface.html', {
        'scan': scan,
        'graph_data': graph_data
    })
