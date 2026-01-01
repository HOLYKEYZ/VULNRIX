import os
import sys
import json
import logging

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'digitalshield.settings')
import django
django.setup()

from vuln_scan.engine.pipeline import SecurityPipeline

def verify():
    # File to test
    target_file = os.path.abspath("vuln_scan/ai_patterns/reverse_shell_sample.py")
    
    print(f"Running Verificaton Scan on: {target_file}")
    
    pipeline = SecurityPipeline()
    # Use 'fast' mode first to test local logic (Semantic/AI Detector)
    result = pipeline.scan_file(target_file, mode='fast')
    
    print(json.dumps(result, indent=2))
    
    # Check if it caught the issue
    if result['status'] == 'VULNERABLE' or (result.get('ai_malicious_risk') and result['ai_malicious_risk']['risk_level'] in ['HIGH', 'CRITICAL']):
        print("\n[SUCCESS] Scanner SUCCESSFULLY detected the vulnerability.")
        return True
    else:
        print("\n[FAILURE] Scanner failed to detect the vulnerability in Fast Mode.")
        return False

if __name__ == "__main__":
    verify()
