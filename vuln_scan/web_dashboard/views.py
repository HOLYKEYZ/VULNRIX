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
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required

# Add vuln_scan directory to path for imports
vuln_scan_dir = Path(__file__).parent.parent.absolute()
if str(vuln_scan_dir) not in sys.path:
    sys.path.insert(0, str(vuln_scan_dir))

# Initialize logger
logger = logging.getLogger("vuln_scan")

# Lazy load pipeline to avoid import errors at startup
_pipeline = None

def get_pipeline():
    """Lazy load the security pipeline."""
    global _pipeline
    if _pipeline is None:
        try:
            from engine.pipeline import SecurityPipeline
            _pipeline = SecurityPipeline()
            logger.info("SecurityPipeline initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize SecurityPipeline: {e}")
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
    """Get the last scan for a user."""
    try:
        from .models import CodeScanHistory
        return CodeScanHistory.objects.filter(user=user).first()
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
        scan_history = get_scan_history(request.user, limit=5)
        
        context = {
            'last_scan': last_scan,
            'scan_history': scan_history,
        }
        
        # If last scan exists, add its findings for display
        if last_scan:
            context['last_findings'] = last_scan.get_findings()
            context['last_result'] = last_scan.get_full_result()
        
        return render(request, "vuln_scan/dashboard.html", context)

    if request.method == "POST":
        logger.info("[VULNRIX] Received POST request for scan")
        file = request.FILES.get("file")
        mode = request.POST.get("mode", "hybrid")
        
        if not file:
            return JsonResponse({"error": "No file uploaded"}, status=400)

        filename = file.name
        logger.info(f"[VULNRIX] File: {filename}, Mode: {mode}")
        ext = os.path.splitext(filename)[1]

        # Create temp file
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8") as tmp:
                code = file.read().decode("utf-8", errors="ignore")
                tmp.write(code)
                tmp_path = tmp.name
                logger.info(f"[VULNRIX] Saved temp file to {tmp_path}")
        except Exception as e:
            logger.error(f"[VULNRIX] Read failed: {e}")
            return JsonResponse({"error": f"Read failed: {e}"}, status=400)

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
        
        try:
            # Only use VirusTotal for non-code files (executables, binaries, etc.)
            vt_result = None
            if not is_code_file:
                try:
                    vt_result = scan_with_virustotal(tmp_path, filename)
                    logger.info(f"[VULNRIX] VirusTotal scan completed for non-code file")
                except Exception as vt_error:
                    logger.warning(f"[VULNRIX] VirusTotal scan failed: {vt_error}")
            else:
                logger.info(f"[VULNRIX] Skipping VirusTotal for code file, using C scanners + LLM")
            
            # Get pipeline for code vulnerability analysis
            pipeline = get_pipeline()
            if pipeline is None:
                return JsonResponse({
                    "status": "ERROR",
                    "error": "Scanner engine not available. Check server logs."
                }, status=500)
            
            # Run Pipeline with Mode
            logger.info(f"[VULNRIX] Starting pipeline scan...")
            start_time = time.time()
            result = pipeline.scan_file(tmp_path, mode=mode)
            duration = time.time() - start_time
            logger.info(f"[VULNRIX] Scan completed in {duration:.2f}s")
            
            # Add metadata
            result["scan_duration"] = round(duration, 2)
            result["filename"] = filename
            result["mode"] = mode
            
            # Add VirusTotal results if available
            if vt_result:
                result["virustotal"] = vt_result
            
            # Calculate file hash for history
            with open(tmp_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Save to scan history
            save_scan_history(request.user, filename, result, mode, file_hash)
            
            return JsonResponse(result)
        except Exception as e:
            logger.error(f"[VULNRIX] Pipeline failed: {e}")
            logger.debug(f"[VULNRIX] Traceback: {__import__('traceback').format_exc()}")
            # Return generic error to users - don't expose internal details
            return JsonResponse({
                "status": "ERROR", 
                "error": "Scan failed. Please try again or contact support.",
                "error_code": "SCAN_ERROR"
            }, status=500)
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)
                logger.info(f"[VULNRIX] Cleaned up temp file")


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
