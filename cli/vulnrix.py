#!/usr/bin/env python3
"""
VULNRIX CLI - Command Line Interface for VULNRIX Security Scanner.

Usage:
    vulnrix scan --type osint --email user@example.com
    vulnrix scan --type code --path ./src --mode deep
    vulnrix breach --type password --value "password123"
    vulnrix monitor --email user@example.com --interval 24h
"""

import argparse
import json
import os
import sys
import requests
from pathlib import Path


# Configuration
DEFAULT_API_URL = os.environ.get('VULNRIX_URL', 'https://api.vulnrix.com')
API_KEY = os.environ.get('VULNRIX_API_KEY', '')


def get_headers():
    """Get API request headers."""
    if not API_KEY:
        print("❌ Error: VULNRIX_API_KEY environment variable not set")
        print("   Set it with: export VULNRIX_API_KEY=your_api_key")
        sys.exit(1)
    
    return {
        'X-API-Key': API_KEY,
        'Content-Type': 'application/json'
    }


def osint_scan(args):
    """Run OSINT scan."""
    print(f"🔍 Starting OSINT scan...")
    
    targets = {}
    if args.email:
        targets['email'] = args.email
    if args.name:
        targets['name'] = args.name
    if args.username:
        targets['username'] = args.username
    if args.domain:
        targets['domain'] = args.domain
    
    if not targets:
        print("❌ Error: At least one target (--email, --name, --username, --domain) required")
        sys.exit(1)
    
    payload = {
        'targets': targets,
        'options': {
            'include_darkweb': not args.no_darkweb,
            'include_social': not args.no_social
        }
    }
    
    try:
        response = requests.post(
            f"{args.api_url}/api/v1/osint/scan",
            headers=get_headers(),
            json=payload,
            timeout=300
        )
        response.raise_for_status()
        result = response.json()
        
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            print_osint_summary(result)
        
        return result
        
    except requests.exceptions.RequestException as e:
        print(f"❌ API Error: {e}")
        sys.exit(1)


def code_scan(args):
    """Run code vulnerability scan."""
    print(f"🔍 Starting code scan on {args.path}...")
    
    scan_path = Path(args.path)
    
    if not scan_path.exists():
        print(f"❌ Error: Path not found: {args.path}")
        sys.exit(1)
    
    # Collect files to scan
    extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php', '.c', '.cpp', '.cs'}
    files = []
    
    if scan_path.is_file():
        files.append(scan_path)
    else:
        for ext in extensions:
            files.extend(scan_path.rglob(f'*{ext}'))
    
    files = files[:100]  # Limit to 100 files
    print(f"📁 Found {len(files)} files to scan")
    
    all_findings = []
    
    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            print(f"   Scanning: {file_path}")
            
            response = requests.post(
                f"{args.api_url}/api/v1/code/scan",
                headers=get_headers(),
                json={
                    'code': code,
                    'filename': str(file_path),
                    'mode': args.mode
                },
                timeout=120
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'VULNERABLE':
                    for finding in result.get('findings', []):
                        finding['file'] = str(file_path)
                        all_findings.append(finding)
            
        except Exception as e:
            print(f"   ⚠️ Error scanning {file_path}: {e}")
    
    # Build result
    result = {
        'status': 'VULNERABLE' if all_findings else 'SAFE',
        'files_scanned': len(files),
        'findings': all_findings,
        'summary': {
            'critical': sum(1 for f in all_findings if f.get('severity', '').lower() == 'critical'),
            'high': sum(1 for f in all_findings if f.get('severity', '').lower() == 'high'),
            'medium': sum(1 for f in all_findings if f.get('severity', '').lower() == 'medium'),
            'low': sum(1 for f in all_findings if f.get('severity', '').lower() == 'low'),
        }
    }
    
    if args.output == 'json':
        print(json.dumps(result, indent=2))
    elif args.output == 'sarif':
        print(json.dumps(to_sarif(result), indent=2))
    else:
        print_code_summary(result)
    
    # Exit with error if findings exceed threshold
    if args.fail_on:
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        threshold = severity_order.get(args.fail_on.lower(), 3)
        
        if result['summary']['critical'] > 0 and threshold <= 4:
            sys.exit(1)
        if result['summary']['high'] > 0 and threshold <= 3:
            sys.exit(1)
        if result['summary']['medium'] > 0 and threshold <= 2:
            sys.exit(1)
        if result['summary']['low'] > 0 and threshold <= 1:
            sys.exit(1)
    
    return result


def breach_check(args):
    """Check for password/email breaches."""
    print(f"🔍 Checking {args.type} for breaches...")
    
    try:
        response = requests.post(
            f"{args.api_url}/api/v1/breach/check",
            headers=get_headers(),
            json={
                'type': args.type,
                'value': args.value
            },
            timeout=30
        )
        response.raise_for_status()
        result = response.json()
        
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            if result.get('found'):
                print(f"⚠️ EXPOSED: Found in {result.get('count', 0):,} breaches!")
            else:
                print("✅ Not found in known breaches")
        
        return result
        
    except requests.exceptions.RequestException as e:
        print(f"❌ API Error: {e}")
        sys.exit(1)


def print_osint_summary(result):
    """Print formatted OSINT results."""
    print("\n" + "="*60)
    print("📊 OSINT Scan Results")
    print("="*60)
    print(f"Risk Score: {result.get('risk_score', 0)}/100")
    
    findings = result.get('findings', {})
    
    if 'email' in findings:
        breaches = findings['email'].get('breaches', {})
        print(f"\n📧 Email Analysis:")
        print(f"   Breaches found: {len(breaches.get('breaches', []))}")
    
    if 'username' in findings:
        print(f"\n👤 Username Analysis:")
        social = findings['username'].get('social_media', {})
        print(f"   Social accounts found: {len(social)}")
    
    print("\n" + "="*60)


def print_code_summary(result):
    """Print formatted code scan results."""
    print("\n" + "="*60)
    print("📊 Code Scan Results")
    print("="*60)
    print(f"Status: {result['status']}")
    print(f"Files scanned: {result['files_scanned']}")
    print(f"\nFindings:")
    print(f"   Critical: {result['summary']['critical']}")
    print(f"   High:     {result['summary']['high']}")
    print(f"   Medium:   {result['summary']['medium']}")
    print(f"   Low:      {result['summary']['low']}")
    
    if result['findings']:
        print("\n📋 Top Findings:")
        for finding in result['findings'][:5]:
            sev = finding.get('severity', 'Unknown')
            print(f"   [{sev}] {finding.get('type', 'Unknown')} in {finding.get('file', 'unknown')}:{finding.get('line', 0)}")
    
    print("="*60)


def to_sarif(result):
    """Convert to SARIF format."""
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "VULNRIX",
                    "version": "2.0.0"
                }
            },
            "results": [
                {
                    "ruleId": f.get('cwe', 'VULN-001'),
                    "level": "error" if f.get('severity', '').lower() in ['critical', 'high'] else "warning",
                    "message": {"text": f.get('reason', f.get('type', 'Vulnerability'))},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.get('file', 'unknown')},
                            "region": {"startLine": f.get('line', 1)}
                        }
                    }]
                }
                for f in result.get('findings', [])
            ]
        }]
    }


def main():
    parser = argparse.ArgumentParser(
        description='VULNRIX Security Scanner CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vulnrix scan --type osint --email user@example.com
  vulnrix scan --type code --path ./src --mode deep --fail-on high
  vulnrix breach --type password --value "password123"
        """
    )
    
    parser.add_argument('--api-url', default=DEFAULT_API_URL, help='VULNRIX API URL')
    parser.add_argument('--output', '-o', choices=['text', 'json', 'sarif'], default='text', help='Output format')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run security scan')
    scan_parser.add_argument('--type', '-t', choices=['osint', 'code'], required=True, help='Scan type')
    
    # OSINT options
    scan_parser.add_argument('--email', '-e', help='Email to scan')
    scan_parser.add_argument('--name', '-n', help='Name to scan')
    scan_parser.add_argument('--username', '-u', help='Username to scan')
    scan_parser.add_argument('--domain', '-d', help='Domain to scan')
    scan_parser.add_argument('--no-darkweb', action='store_true', help='Skip dark web scan')
    scan_parser.add_argument('--no-social', action='store_true', help='Skip social media scan')
    
    # Code scan options
    scan_parser.add_argument('--path', '-p', default='.', help='Path to scan')
    scan_parser.add_argument('--mode', '-m', choices=['fast', 'hybrid', 'deep'], default='hybrid', help='Scan mode')
    scan_parser.add_argument('--fail-on', choices=['critical', 'high', 'medium', 'low'], help='Fail on severity')
    
    # Breach command
    breach_parser = subparsers.add_parser('breach', help='Check for breaches')
    breach_parser.add_argument('--type', '-t', choices=['password', 'email'], required=True, help='Check type')
    breach_parser.add_argument('--value', '-v', required=True, help='Value to check')
    
    # Version
    parser.add_argument('--version', action='version', version='VULNRIX CLI 2.0.0')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    # Copy api_url to args for all commands
    if hasattr(args, 'api_url'):
        pass
    else:
        args.api_url = DEFAULT_API_URL
    
    if args.command == 'scan':
        if args.type == 'osint':
            osint_scan(args)
        else:
            code_scan(args)
    elif args.command == 'breach':
        breach_check(args)


if __name__ == '__main__':
    main()
