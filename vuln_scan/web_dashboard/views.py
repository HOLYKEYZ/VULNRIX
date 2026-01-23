"""
Django views for vuln_scan web dashboard.
Integrated into VULNRIX platform.
"""

import os
import sys
import tempfile
import time
import logging
import hashlib
import requests
from pathlib import Path
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.conf import settings # Fix: Import settings
from django.utils import timezone

# Add vuln_scan directory to path for imports

# SEO Views
@require_http_methods(["GET"])
def robots_txt(request):
    """Serve robots.txt for search engines."""
    content = """User-agent: *
Allow: /
Disallow: /dashboard/
Disallow: /vuln-node/
Disallow: /admin/

User-agent: GPTBot
Allow: /
Disallow: /dashboard/

Sitemap: https://vulnrix.com/sitemap.xml
"""
    return HttpResponse(content, content_type="text/plain")

@require_http_methods(["GET"])
def sitemap_xml(request):
    """Serve sitemap.xml for SEO."""
    base_url = "https://vulnrix.com"
    pages = [
        "",  # Home
        "/docs/",
        "/accounts/login/",
        "/accounts/register/",
    ]
    
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n'
    xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    
    for page in pages:
        xml += '  <url>\n'
        xml += f'    <loc>{base_url}{page}</loc>\n'
        xml += '    <changefreq>weekly</changefreq>\n'
        xml += '    <priority>0.8</priority>\n'
        xml += '  </url>\n'
        
    xml += '</urlset>'
    return HttpResponse(xml, content_type="application/xml")
vuln_scan_dir = Path(__file__).parent.parent.absolute()
if str(vuln_scan_dir) not in sys.path:
    sys.path.insert(0, str(vuln_scan_dir))

from ..services.llm_dispatcher import LLMDispatcher

# Initialize logger
logger = logging.getLogger("vuln_scan")

# Lazy load pipeline to avoid import errors at startup
_pipeline = None

def get_pipeline():
    """Lazy load the security pipeline."""
    global _pipeline
    if _pipeline is None:
        try:
            # Fix: Use full module path for Django context
            from vuln_scan.engine.pipeline import SecurityPipeline
            _pipeline = SecurityPipeline()
            logger.info("[VULNRIX] SecurityPipeline initialized successfully (AI verification enabled)")
        except Exception as e:
            logger.error(f"[VULNRIX] Failed to initialize SecurityPipeline: {e}")
            import traceback
            traceback.print_exc()
            _pipeline = None
    return _pipeline


def save_scan_history(user, filename, result, mode, file_hash=""):
    """Save scan result to history."""
    try:
        from .models import CodeScanHistory
        
        findings = result.get('findings', []) or result.get('semantic_hints', [])
        summary = result.get('summary', {})
        
        scan = CodeScanHistory(
            user=user,
            filename=filename,
            language=result.get('language', ''),
            mode=mode,
            status=result.get('status', 'UNKNOWN'),
            risk_score=result.get('risk_score', 0),
            total_findings=summary.get('total', len(findings)),
            critical_count=summary.get('critical', 0),
            high_count=summary.get('high', 0),
            medium_count=summary.get('medium', 0),
            low_count=summary.get('low', 0),
            scan_duration=result.get('scan_duration', 0),
            file_hash=file_hash
        )
        scan.set_findings(findings)
        scan.set_full_result(result)
        scan.save()
        logger.info(f"[VULNRIX] Saved scan history for {filename}")
        return scan
    except Exception as e:
        logger.error(f"[VULNRIX] Failed to save scan history: {e}")
        return None


def get_last_scan(user):
    """Get the last scan (File or Project) for a user."""
    try:
        from .models import CodeScanHistory, ScanProject
        
        last_file = CodeScanHistory.objects.filter(user=user).order_by('-created_at').first()
        last_proj = ScanProject.objects.filter(user=user).order_by('-created_at').first()
        
        if not last_file and not last_proj:
            return None
            
        if last_file and not last_proj:
            return last_file
            
        if last_proj and not last_file:
            # Adapt project to look like history for template compatibility
            last_proj.total_findings = last_proj.risk_score # approximate for now or add logic
            return last_proj
            
        # Both exist, return newer
        if last_proj.created_at > last_file.created_at:
            last_proj.total_findings = last_proj.risk_score # hack compatibility
            return last_proj
            
        return last_file
    except Exception as e:
        logger.error(f"[VULNRIX] Failed to get last scan: {e}")
        return None


def get_scan_history(user, limit=10):
    """Get scan history for a user."""
    try:
        from .models import CodeScanHistory
        return list(CodeScanHistory.objects.filter(user=user)[:limit])
    except Exception as e:
        logger.error(f"[VULNRIX] Failed to get scan history: {e}")
        return []


@login_required
@require_http_methods(["GET", "POST"])
def dashboard(request):
    """
    Main dashboard view: renders the upload interface on GET,
    processes file upload and scan on POST.
    """
    if request.method == "GET":
        # Get last scan and history for display
        last_scan = get_last_scan(request.user)
        scan_history = get_scan_history(request.user, limit=10)
        
        # Get project scan history
        from .models import ScanProject
        project_history = list(ScanProject.objects.filter(user=request.user).order_by('-created_at')[:10])
        
        # Combine and sort all scans by created_at (newest first)
        combined_history = []
        for scan in scan_history:
            combined_history.append({
                'type': 'file',
                'id': scan.id,
                'name': scan.filename,
                'status': scan.status,
                'created_at': scan.created_at,
                'detail': f"{scan.total_findings} issues",
            })
        for project in project_history:
            combined_history.append({
                'type': 'project',
                'id': project.id,
                'name': project.name,
                'status': project.status,
                'created_at': project.created_at,
                'detail': f"{project.total_files} files",
            })
        
        # Sort by created_at descending (newest first)
        combined_history.sort(key=lambda x: x['created_at'], reverse=True)
        combined_history = combined_history[:10]  # Limit to 10 total
        
        context = {
            'last_scan': last_scan,
            'scan_history': scan_history,
            'project_history': project_history,
            'combined_history': combined_history,
        }
        
        # If last scan exists, add its findings for display
        if last_scan:
            context['last_findings'] = last_scan.get_findings()
            context['last_result'] = last_scan.get_full_result()
            
            # Calculate Score/Grade
            crit, high, med, low = 0, 0, 0, 0
            try:
                if hasattr(last_scan, 'critical_count'): # CodeScanHistory
                    crit = last_scan.critical_count
                    high = last_scan.high_count
                    med = last_scan.medium_count
                    low = last_scan.low_count
                else: # ScanProject
                    for f in last_scan.file_results.all():
                        if f.severity == 'CRITICAL': crit += 1
                        elif f.severity == 'HIGH': high += 1
                        elif f.severity == 'MEDIUM': med += 1
                        elif f.severity == 'LOW': low += 1
            except Exception:
                pass # safely fallback to 0/0/0/0 -> Grade A (100%)
                
            metrics = calculate_security_metrics(crit, high, med, low)
            context['security_grade'] = metrics['grade']
            context['security_score'] = metrics['score']
        
        return render(request, "vuln_scan/dashboard_fixed.html", context)

    if request.method == "POST":
        tmp_path = None
        try:
            logger.info("[VULNRIX] Received POST request for scan")
            file = request.FILES.get("file")
            mode = request.POST.get("mode", "hybrid")
            
            if not file:
                return JsonResponse({"error": "No file uploaded"}, status=400)

            # Enforce file size limits
            size_limits = {
                'fast': 20 * 1024 * 1024,   # 20MB
                'hybrid': 2 * 1024 * 1024,  # 2MB
                'deep': 1 * 1024 * 1024     # 1MB
            }
            limit = size_limits.get(mode, 2 * 1024 * 1024)
            
            if file.size > limit:
                return JsonResponse({
                    "error": f"File too large for {mode} mode. Limit is {limit/1024/1024:.1f}MB."
                }, status=413)

            filename = file.name
            logger.info(f"[VULNRIX] File: {filename}, Mode: {mode}, Size: {file.size}")
            ext = os.path.splitext(filename)[1]

            # Create temp file
            with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8") as tmp:
                code = file.read().decode("utf-8", errors="ignore")
                tmp.write(code)
                tmp_path = tmp.name
                logger.info(f"[VULNRIX] Saved temp file to {tmp_path}")

            # Define code file extensions that should NOT go to VirusTotal
            CODE_EXTENSIONS = {
                '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.php', '.rb',
                '.c', '.cpp', '.h', '.hpp', '.cs', '.swift', '.kt', '.kts', '.rs',
                '.sql', '.sh', '.bash', '.ps1', '.yaml', '.yml', '.json', '.xml',
                '.html', '.htm', '.css', '.scss', '.sass', '.less', '.vue', '.svelte',
                '.scala', '.groovy', '.pl', '.pm', '.lua', '.r', '.m', '.mm', '.asm',
                '.vb', '.vbs', '.bat', '.cmd', '.psm1', '.psd1', '.tf', '.hcl',
                '.dockerfile', '.env', '.ini', '.cfg', '.conf', '.toml', '.properties',
                '.md', '.txt', '.rst', '.tex'
            }
            
            is_code_file = ext.lower() in CODE_EXTENSIONS
            
            # VirusTotal Scan (for non-code)
            vt_result = None
            if not is_code_file:
                try:
                    vt_result = scan_with_virustotal(tmp_path, filename)
                    logger.info(f"[VULNRIX] VirusTotal scan completed")
                except Exception as vt_error:
                    logger.warning(f"[VULNRIX] VirusTotal scan failed: {vt_error}")
            
            # Code Analysis Pipeline
            pipeline = get_pipeline()
            
            # Retry once if pipeline fails to initialize (fixes first-scan race condition)
            if pipeline is None:
                logger.warning("[VULNRIX] Pipeline was None, retrying initialization...")
                import time
                time.sleep(0.5)
                pipeline = get_pipeline()
                
            if pipeline is None:
                raise Exception("Scanner engine unavailable (Import Error)")
            
            logger.info(f"[VULNRIX] Starting pipeline scan...")
            start_time = time.time()
            
            # --- SNYK REMOVED (Local Engine Only) ---
            # Snyk service deprecated in favor of hybrid local pipeline
            logger.info("[VULNRIX] Starting pipeline scan (Local Engine)...")

            
            # --- LOCAL PIPELINE ANALYSIS ---
            result = pipeline.scan_file(tmp_path, mode=mode)
            duration = time.time() - start_time
            
            # Merge Snyk findings into result
            if snyk_result and snyk_result.get('findings'):
                existing_findings = result.get('findings', [])
                snyk_findings = snyk_result.get('findings', [])
                # Add source tag to differentiate
                for f in snyk_findings:
                    f['source'] = 'snyk'
                # Prepend Snyk findings (they come first as "external validation")
                result['findings'] = snyk_findings + existing_findings
                result['snyk_summary'] = snyk_result.get('summary', {})
                logger.info(f"[VULNRIX] Merged {len(snyk_findings)} Snyk findings")
            
            # Enrich result
            result["scan_duration"] = round(duration, 2)
            result["filename"] = filename
            result["mode"] = mode
            if vt_result:
                result["virustotal"] = vt_result
            
            # Calculate hash
            with open(tmp_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Save history
            save_scan_history(request.user, filename, result, mode, file_hash)
            
            # Calculate Grade for Frontend
            findings = result.get('findings', [])
            crit = len([f for f in findings if f.get('severity', '').lower() == 'critical'])
            high = len([f for f in findings if f.get('severity', '').lower() == 'high'])
            med = len([f for f in findings if f.get('severity', '').lower() == 'medium'])
            low = len([f for f in findings if f.get('severity', '').lower() == 'low'])
            
            metrics = calculate_security_metrics(crit, high, med, low)
            result['security_grade'] = metrics['grade']
            result['security_score'] = metrics['score']
            
            return JsonResponse(result)

        except Exception as e:
            logger.error(f"[VULNRIX] Post Error: {e}")
            logger.debug(f"Traceback: {__import__('traceback').format_exc()}")
            return JsonResponse({
                "status": "ERROR", 
                "error": f"Scan failed: {str(e)}",
                "error_code": "SCAN_ERROR"
            }, status=500)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
                logger.info(f"[VULNRIX] Temp file cleaned")


def scan_with_virustotal(file_path: str, filename: str) -> dict:
    """
    Scan file with VirusTotal API.
    Falls back to local hash analysis if API fails.
    """
    api_key = os.getenv('VIRUS_TOTAL_API_KEY')
    if not api_key:
        raise ValueError("VirusTotal API key not configured")
    
    # Calculate file hash
    with open(file_path, 'rb') as f:
        file_content = f.read()
        file_hash = hashlib.sha256(file_content).hexdigest()
    
    headers = {'x-apikey': api_key}
    
    try:
        # First, check if file is already analyzed
        check_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(check_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {
                'source': 'virustotal_api',
                'file_hash': file_hash,
                'filename': filename,
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'total_engines': sum(stats.values()) if stats else 0,
                'scan_date': data.get('data', {}).get('attributes', {}).get('last_analysis_date'),
                'permalink': f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        elif response.status_code == 404:
            # File not in VT database, upload it
            upload_url = "https://www.virustotal.com/api/v3/files"
            with open(file_path, 'rb') as f:
                files = {'file': (filename, f, 'application/octet-stream')}
                upload_response = requests.post(upload_url, headers=headers, files=files, timeout=30)
            
            if upload_response.status_code == 200:
                upload_data = upload_response.json()
                analysis_id = upload_data.get('data', {}).get('id')
                return {
                    'source': 'virustotal_api',
                    'file_hash': file_hash,
                    'filename': filename,
                    'status': 'uploaded_for_analysis',
                    'analysis_id': analysis_id,
                    'message': 'File uploaded to VirusTotal for analysis. Results will be available shortly.',
                    'permalink': f"https://www.virustotal.com/gui/file/{file_hash}"
                }
            else:
                raise ValueError(f"Upload failed: {upload_response.status_code}")
        else:
            raise ValueError(f"VT API error: {response.status_code}")
            
    except Exception as e:
        # Fallback to local analysis
        logger.warning(f"VirusTotal API failed, using local analysis: {e}")
        
        # Basic file analysis
        file_size = os.path.getsize(file_path)
        file_ext = os.path.splitext(filename)[1].lower()
        
        # Simple heuristics
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.com', '.vbs', '.js']
        is_suspicious = file_ext in suspicious_extensions
        
        return {
            'source': 'local_fallback',
            'status': 'UNKNOWN',  # Be honest - we cannot determine safety
            'file_hash': file_hash,
            'filename': filename,
            'file_size': file_size,
            'file_extension': file_ext,
            'suspicious_extension': is_suspicious,
            'warning': 'Cannot determine safety without malware scanning API.',
            'message': 'VirusTotal API unavailable. Extension-based analysis only.',
            'recommendation': 'Upload manually to virustotal.com for complete analysis'
        }


@login_required
@require_http_methods(["GET"])
def get_scan_result(request, scan_id):
    """Get a specific scan result by ID."""
    try:
        from .models import CodeScanHistory
        
        scan = CodeScanHistory.objects.filter(id=scan_id, user=request.user).first()
        if not scan:
            return JsonResponse({"error": "Scan not found"}, status=404)
        
        result = scan.get_full_result()
        result['scan_id'] = scan.id
        result['filename'] = scan.filename
        result['language'] = scan.language
        result['status'] = scan.status
        result['created_at'] = scan.created_at.isoformat()
        
        return JsonResponse(result)
    except Exception as e:
        logger.error(f"[VULNRIX] Failed to get scan result: {e}")
        return JsonResponse({"error": str(e)}, status=500)


@login_required
@require_http_methods(["GET", "POST"])
def virustotal_scan(request):
    """VirusTotal-only file scanning for non-developers."""
    if request.method == "GET":
        return render(request, "vuln_scan/virustotal.html")
    
    # POST - handle file upload
    file = request.FILES.get("file")
    if not file:
        return JsonResponse({"error": "No file uploaded"}, status=400)
    
    filename = file.name
    tmp_path = None
    
    try:
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            for chunk in file.chunks():
                tmp.write(chunk)
            tmp_path = tmp.name
        
        # Scan with VirusTotal
        result = scan_with_virustotal(tmp_path, filename)
        result["filename"] = filename
        
        return JsonResponse(result)
    except Exception as e:
        logger.error(f"[VULNRIX] VirusTotal scan failed: {e}")
        return JsonResponse({"error": str(e)}, status=500)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


@login_required
@require_http_methods(["GET"])
def get_scan_result(request, scan_id):
    """Get a historical scan result by ID."""
    try:
        from .models import CodeScanHistory
        
        scan = CodeScanHistory.objects.filter(id=scan_id, user=request.user).first()
        
        if not scan:
            return JsonResponse({"success": False, "error": "Scan not found"}, status=404)
        
        result = scan.get_full_result()
        
        return JsonResponse({
            "success": True,
            "result": result,
            "filename": scan.filename,
            "created_at": scan.created_at.isoformat(),
            "status": scan.status
        })
    except Exception as e:
        logger.error(f"[VULNRIX] Failed to get scan result: {e}")
        return JsonResponse({"success": False, "error": str(e)}, status=500)


# -------------------------------------------------------------------------
# REPO / PROJECT SCAN VIEWS (Re-implemented safely)
# -------------------------------------------------------------------------

import shutil
from django.utils import timezone
from ..services.repo_fetcher import clone_repo
from ..services.result_aggregator import update_project_stats, create_file_result, calculate_security_metrics
from ..services.llm_dispatcher import LLMDispatcher
from ..services.file_filter import is_safe_file
from ..services.scan_limiter import check_and_increment_usage, DailyQuotaExceeded

SCAN_TEMP_BASE = Path(tempfile.gettempdir()) / "vulnrix_scans"
SCAN_TEMP_BASE.mkdir(exist_ok=True)


@login_required
@require_http_methods(["POST"])
def start_repo_scan(request):
    """Start a Repository Scan (Git Clone)."""
    try:
        from .models import ScanProject, ScanFileResult
        
        repo_url = request.POST.get('repo_url')
        if not repo_url:
            return JsonResponse({"error": "Missing repo_url"}, status=400)
            
        # Check Daily Limit
        try:
            check_and_increment_usage(request.user)
        except DailyQuotaExceeded as e:
            return JsonResponse({"error": str(e), "code": "DAILY_LIMIT_EXCEEDED"}, status=403)
            
        # Create Project
        project_name = repo_url.split('/')[-1].replace('.git', '')
        project = ScanProject.objects.create(
            user=request.user,
            name=project_name,
            repo_url=repo_url,
            status='INITIALIZING'
        )
        
        # Directory setup
        project_dir = SCAN_TEMP_BASE / str(project.id)
        if project_dir.exists():
            shutil.rmtree(project_dir)
        project_dir.mkdir(parents=True, exist_ok=True)
        
        # Clone
        success, error_msg = clone_repo(repo_url, str(project_dir))
        if not success:
            project.status = 'ERROR'
            project.save()
            return JsonResponse({"error": f"Clone Failed: {error_msg}"}, status=400)
            
        # Discover files
        files_created = []
        
        # File Limit: 500 (user tested 133 successfully)
        current_limit = 500
            
        for root, _, files in os.walk(project_dir):
            for file in files:
                full_path = Path(root) / file
                rel_path = full_path.relative_to(project_dir)
                
                # Filter safe files (code only)
                if is_safe_file(str(full_path)):
                    res = ScanFileResult.objects.create(
                        project=project,
                        filename=str(rel_path).replace('\\', '/'),
                        status='PENDING'
                    )
                    files_created.append(res)
                    
                    if len(files_created) >= current_limit:
                        break
            if len(files_created) >= current_limit:
                break
        
        # Check if we hit the limit
        exceeded_limit = len(files_created) >= current_limit

        project.total_files = len(files_created)
        project.status = 'READY'
        project.save()
        
        response_data = {
            "project_id": project.id,
            "total_files": project.total_files,
            "status": "READY",
            "limit_exceeded": exceeded_limit,
            "max_files": current_limit
        }
            
        return JsonResponse(response_data)
        
    except Exception as e:
        logger.error(f"Repo Scan Start Failed: {e}")
        return JsonResponse({"error": str(e)}, status=500)



@login_required
@require_http_methods(["POST"])
def scan_next_file(request, project_id):
    """
    Process next pending file for project.
    Robust error handling to return JSON.
    """
    try:
        from .models import ScanProject
        project = ScanProject.objects.get(id=project_id, user=request.user)
    except Exception:
        return JsonResponse({"error": "Project not found"}, status=404)
        
    try:
        # Get next pending
        next_file = project.file_results.filter(status='PENDING').first()
        
        if not next_file:
            # Check if all done
            if not project.file_results.filter(status='PROCESSING').exists():
                # Aggregate Risk Score
                total_risk = sum((f.risk_score or 0) for f in project.file_results.all())
                project.risk_score = total_risk
                
                project.status = 'COMPLETED'
                project.completed_at = timezone.now()
                # Cleanup
                project_dir = SCAN_TEMP_BASE / str(project.id)
                if project_dir.exists():
                    shutil.rmtree(str(project_dir), ignore_errors=True)
                project.save()
                return JsonResponse({"status": "COMPLETED"})
            else:
                return JsonResponse({"status": "WAITING"}) # Others are processing
        
        # Lock file
        next_file.status = 'PROCESSING'
        next_file.save()
        
        # Verify File Exists
        project_dir = SCAN_TEMP_BASE / str(project.id)
        abs_path = (project_dir / next_file.filename).resolve()
        
        if not abs_path.exists():
             next_file.status = 'ERROR'
             next_file.save()
             return JsonResponse({"filename": next_file.filename, "status": "ERROR", "error": "File missing"})

        # Pipeline Dispatch
        pipeline = get_pipeline()
        dispatcher = LLMDispatcher(pipeline)
        
        # Read file content
        try:
             with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                 code_content = f.read()
             file_size_mb = getattr(abs_path.stat(), 'st_size', 0) / (1024 * 1024)
        except Exception as read_err:
             code_content = ""
             file_size_mb = 0

        # Determine Scan Strategy (Local Engine Only)
        scan_mode = request.POST.get('mode', 'hybrid')
        
        # Skip huge files (>2MB) to prevent memory crashes
        if file_size_mb > 2.0:
            result = {
                'status': 'SKIPPED',
                'risk_score': 0,
                'findings': [],
                'reason': 'File too large (>2MB)'
            }
        else:
            # Run Local Pipeline (Regex + Semantic + AI Verification)
            result = dispatcher.scan_file(str(abs_path), mode=scan_mode)

        # Update Result
        next_file.status = 'COMPLETED' if result.get('status') != 'ERROR' else 'ERROR'
        next_file.risk_score = result.get('risk_score', 0)
        
        findings = result.get('findings', [])
        if findings:
            # Fix: Handle None score to prevent 500 Error
            score = result.get('risk_score') or 0
            next_file.severity = 'HIGH' if score > 70 else 'MEDIUM'
        else:
            next_file.severity = 'SAFE'
            
        next_file.set_findings(findings)
        next_file.save()
        
        # Aggregate
        update_project_stats(project)
        
        return JsonResponse({
            "status": "PROCESSED",
            "filename": next_file.filename,
            "severity": next_file.severity,
            "risk": next_file.risk_score,
            "findings": result.get('findings', [])
        })
        
    except Exception as e:
        logger.error(f"Scan Loop Error: {e}")
        return JsonResponse({"error": str(e)}, status=500)


@login_required
@require_http_methods(["GET"])
def project_status(request, project_id):
    """Return project status and findings."""
    try:
        from .models import ScanProject
        project = ScanProject.objects.get(id=project_id, user=request.user)
        
        findings_data = []
        crit, high, med, low = 0, 0, 0, 0
        
        # Return ALL findings so analysis isn't empty
        for f in project.file_results.all().order_by('-risk_score'):
            # Tally aggregation
            if f.severity == 'CRITICAL': crit += 1
            elif f.severity == 'HIGH': high += 1
            elif f.severity == 'MEDIUM': med += 1
            elif f.severity == 'LOW': low += 1
            
            # Extract detailed findings
            file_findings = f.get_findings()
            
            if file_findings:
                # Add each individual finding
                for finding in file_findings:
                    findings_data.append({
                        "filename": f.filename,
                        "severity": finding.get('severity', f.severity),
                        "type": finding.get('type', 'Unknown'),
                        "risk_score": f.risk_score,
                        "status": f.status,
                        "line": finding.get('line', finding.get('location', {}).get('line', '-')),
                        "description": finding.get('description', ''),
                        "recommendation": finding.get('recommendation', ''),
                        "location": finding.get('location', {}),
                        "file_id": f.id
                    })
            elif f.status != 'SAFE' and f.severity != 'SAFE':
                # Fallback for files with status but no detailed JSON (Only if NOT SAFE)
                findings_data.append({
                     "filename": f.filename,
                     "severity": f.severity,
                     "type": "File Status", 
                     "risk_score": f.risk_score,
                     "status": f.status,
                     "description": f"File marked as {f.severity} (No detailed findings)",
                     "file_id": f.id
                })
            
        metrics = calculate_security_metrics(crit, high, med, low)
            
        return JsonResponse({
            "status": project.status,
            "total": project.total_files,
            "processed": project.processed_files,
            "normalized_score": metrics['score'],
            "grade": metrics['grade'],
            "project_name": project.name,
            "findings": findings_data,
            "repo_url": project.repo_url
        })
    except Exception as e:
        logger.error(f"Project Status Error: {e}")
        return JsonResponse({"error": str(e)}, status=500)


@login_required
@require_http_methods(["GET"])
def project_file_details(request, project_id, file_id):
    """Get detailed findings for a specific file in a project."""
    try:
        from .models import ScanProject, ScanFileResult
        
        project = ScanProject.objects.get(id=project_id, user=request.user)
        file_result = ScanFileResult.objects.get(id=file_id, project=project)
        
        findings = file_result.get_findings()
        
        return JsonResponse({
            "filename": file_result.filename,
            "severity": file_result.severity,
            "risk_score": file_result.risk_score,
            "status": file_result.status,
            "findings": findings,
            "project_name": project.name
        })
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@ensure_csrf_cookie
@require_http_methods(["GET", "POST"])
def home(request):
    """
    Public Welcome Page & Demo Scanner.
    Limit: 2 scans per guest session.
    """
    if request.method == "GET":
        return render(request, "vuln_scan/home.html")
        
    if request.method == "POST":
        try:
            # 1. Guest Rate Limit Check
            if not request.user.is_authenticated:
                guest_scans = request.session.get('guest_scans', 0)
                if guest_scans >= 2:
                    return JsonResponse({
                        "error": "Guest limit reached",
                        "limit_reached": True,
                        "guest_scans": guest_scans
                    }, status=403)
                
                # Increment scan count
                request.session['guest_scans'] = guest_scans + 1
                request.session.modified = True
            
            # 2. File Upload Handling
            file = request.FILES.get("file")
            if not file:
                return JsonResponse({"error": "No file uploaded"}, status=400)
                
            # Check Daily Limit
            try:
                from ..services.scan_limiter import check_and_increment_usage, DailyQuotaExceeded
                check_and_increment_usage(request.user)
            except DailyQuotaExceeded as e:
                return JsonResponse({"error": str(e), "code": "DAILY_LIMIT_EXCEEDED"}, status=403)
            
            # Create temp file
            temp_dir = Path(tempfile.gettempdir()) / "vulnrix_guest"
            temp_dir.mkdir(exist_ok=True)
            
            # Use original filename but secure it (basic check)
            original_name = file.name
            safe_name = "".join(c for c in original_name if c.isalnum() or c in "._-")
            if not safe_name: safe_name = "guest_upload.tmp"
                
            tmp_path = temp_dir / f"guest_{int(time.time())}_{safe_name}"
            
            with open(tmp_path, "wb+") as destination:
                for chunk in file.chunks():
                    destination.write(chunk)
            
            # 3. Scanning
            pipeline = get_pipeline()
            dispatcher = LLMDispatcher(pipeline)
            
            # Use 'fast' mode for public demo to save resources
            result = dispatcher.scan_file(str(tmp_path), mode="fast")
            
            # Cleanup
            try:
                os.remove(tmp_path)
            except:
                pass
            
            guest_count = request.session.get('guest_scans', 0) if not request.user.is_authenticated else 0
            
            return JsonResponse({
                "status": "success",
                "risk_score": result.get('risk_score', 0),
                "findings": result.get('findings', []),
                "guest_scans": guest_count
            })
            
        except Exception as e:
            logger.error(f"Home Scan Error: {e}")
            return JsonResponse({"error": str(e)}, status=500)
