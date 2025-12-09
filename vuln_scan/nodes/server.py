"""
Distributed Scanning Node
Exposes the Security Pipeline via a REST API.
"""

import os
import sys
import tempfile
import logging
from pathlib import Path
from flask import Flask, request, jsonify

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from engine.pipeline import SecurityPipeline

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("node_server")

# Initialize Pipeline (Singleton)
pipeline = SecurityPipeline()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "node": os.getenv("NODE_ID", "local")})

@app.route('/scan', methods=['POST'])
def scan():
    data = request.json
    if not data or 'code' not in data:
        return jsonify({"error": "Missing code"}), 400
        
    code = data['code']
    filename = data.get('filename', 'scan_target.py')
    
    # Create temp file
    ext = os.path.splitext(filename)[1]
    with tempfile.NamedTemporaryFile(mode='w', suffix=ext, delete=False, encoding='utf-8') as tmp:
        tmp.write(code)
        tmp_path = tmp.name
        
    try:
        # Run Scan
        result = pipeline.scan_file(tmp_path)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        return jsonify({"status": "ERROR", "error": str(e)}), 500
        
    finally:
        # Cleanup
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
