"""
Django views for vuln_scan distributed node server.
Integrated into VULNRIX platform.
"""

import os
import sys
import tempfile
import logging
from pathlib import Path
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

# Add vuln_scan directory to path for imports
vuln_scan_dir = Path(__file__).parent.parent.absolute()
if str(vuln_scan_dir) not in sys.path:
    sys.path.insert(0, str(vuln_scan_dir))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vuln_scan_node")

# Lazy load pipeline
_pipeline = None

def get_pipeline():
    """Lazy load the security pipeline."""
    global _pipeline
    if _pipeline is None:
        try:
            from engine.pipeline import SecurityPipeline
            _pipeline = SecurityPipeline()
            logger.info("Node SecurityPipeline initialized")
        except Exception as e:
            logger.error(f"Failed to initialize pipeline: {e}")
            _pipeline = None
    return _pipeline


@csrf_exempt
@require_http_methods(["GET"])
def health(request):
    """Health check endpoint."""
    return JsonResponse({"status": "ok", "node": os.getenv("NODE_ID", "local")})


@csrf_exempt
@require_http_methods(["POST"])
def scan(request):
    """Scan endpoint: accepts JSON with code and returns vulnerability results."""
    import json
    try:
        data = json.loads(request.body)
    except (TypeError, json.JSONDecodeError):
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    if not data or "code" not in data:
        return JsonResponse({"error": "Missing code"}, status=400)

    code = data["code"]
    filename = data.get("filename", "scan_target.py")

    # Get pipeline
    pipeline = get_pipeline()
    if pipeline is None:
        return JsonResponse({
            "status": "ERROR",
            "error": "Scanner engine not available"
        }, status=500)

    # Create temp file
    ext = os.path.splitext(filename)[1]
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8") as tmp:
            tmp.write(code)
            tmp_path = tmp.name

        # Run Scan
        result = pipeline.scan_file(tmp_path)
        return JsonResponse(result)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        return JsonResponse({"status": "ERROR", "error": str(e)}, status=500)
    finally:
        # Cleanup
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
