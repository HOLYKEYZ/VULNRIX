#!/usr/bin/env python3
"""
VULNRIX CLI - Command Line Interface for VULNRIX Security Scanner.

Usage:
    vulnrix osint --email user@example.com
    vulnrix code --path ./src --mode deep
    vulnrix breach --value "password123"
    vulnrix phone --number +1234567890
    vulnrix domain --name example.com
    vulnrix ip --address 1.2.3.4
    vulnrix username --handle johndoe
    vulnrix release --version 1.0.0
"""

import argparse
import json
import os
import sys
import subprocess
from pathlib import Path

import requests
from rich.console import Console
from rich.table import Table
from rich import print as rprint

console = Console()


DEFAULT_API_URL = os.environ.get('VULNRIX_URL', 'http://localhost:8000')
API_KEY = os.environ.get('VULNRIX_API_KEY', '')


def get_headers():
    """Get API request headers."""
    if not API_KEY:
        console.print("[yellow]Warning: VULNRIX_API_KEY not set. Some features may not work.[/yellow]")
    
    headers = {
        'Content-Type': 'application/json'
    }
    if API_KEY:
        headers['X-API-Key'] = API_KEY
    return headers


def osint_scan(args):
    """Run OSINT scan."""
    console.print(f"[cyan]Starting OSINT scan...[/cyan]")
    
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
        console.print("[red]Error: At least one target (--email, --name, --username, --domain) required[/red]")
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
        console.print(f"[red]API Error: {e}[/red]")
        sys.exit(1)


def code_scan(args):
    """Run code vulnerability scan."""
    console.print(f"[cyan]Starting code scan on {args.path}...[/cyan]")
    
    scan_path = Path(args.path)
    
    if not scan_path.exists():
        console.print(f"[red]Error: Path not found: {args.path}[/red]")
        sys.exit(1)
    
    extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php', '.c', '.cpp', '.cs'}
    files = []
    
    if scan_path.is_file():
        files.append(scan_path)
    else:
        for ext in extensions:
            files.extend(scan_path.rglob(f'*{ext}'))
    
    files = files[:100]
    console.print(f"[green]Found {len(files)} files to scan[/green]")
    
    all_findings = []
    
    for file_path in files:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            
            console.print(f"  Scanning: {file_path}")
            
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
            console.print(f"  [yellow]Error scanning {file_path}: {e}[/yellow]")
    
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
    console.print(f"[cyan]Checking breach for: {args.value}[/cyan]")
    
    check_type = 'password' if '@' not in args.value else 'email'
    
    try:
        response = requests.post(
            f"{args.api_url}/api/v1/breach/check",
            headers=get_headers(),
            json={
                'type': check_type,
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
                console.print(f"[red]EXPOSED: Found in {result.get('count', 0):,} breaches![/red]")
            else:
                console.print("[green]Not found in known breaches[/green]")
        
        return result
        
    except requests.exceptions.RequestException as e:
        console.print(f"[red]API Error: {e}[/red]")
        sys.exit(1)


def phone_scan(args):
    """Scan phone number."""
    console.print(f"[cyan]Scanning phone: {args.number}[/cyan]")
    
    try:
        response = requests.post(
            f"{args.api_url}/api/v1/scan/phone",
            headers=get_headers(),
            json={'phone': args.number},
            timeout=60
        )
        response.raise_for_status()
        result = response.json()
        
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            print_phone_summary(result)
        
        return result
        
    except requests.exceptions.RequestException as e:
        console.print(f"[red]API Error: {e}[/red]")
        sys.exit(1)


def domain_scan(args):
    """Scan domain."""
    console.print(f"[cyan]Scanning domain: {args.name}[/cyan]")
    
    try:
        response = requests.post(
            f"{args.api_url}/api/v1/scan/domain",
            headers=get_headers(),
            json={'domain': args.name},
            timeout=60
        )
        response.raise_for_status()
        result = response.json()
        
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            print_domain_summary(result)
        
        return result
        
    except requests.exceptions.RequestException as e:
        console.print(f"[red]API Error: {e}[/red]")
        sys.exit(1)


def ip_scan(args):
    """Scan IP address."""
    console.print(f"[cyan]Scanning IP: {args.address}[/cyan]")
    
    try:
        response = requests.post(
            f"{args.api_url}/api/v1/scan/ip",
            headers=get_headers(),
            json={'ip': args.address},
            timeout=60
        )
        response.raise_for_status()
        result = response.json()
        
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            print_ip_summary(result)
        
        return result
        
    except requests.exceptions.RequestException as e:
        console.print(f"[red]API Error: {e}[/red]")
        sys.exit(1)


def username_scan(args):
    """Scan username across social media."""
    console.print(f"[cyan]Scanning username: {args.handle}[/cyan]")
    
    try:
        response = requests.post(
            f"{args.api_url}/api/v1/scan/username",
            headers=get_headers(),
            json={'username': args.handle},
            timeout=60
        )
        response.raise_for_status()
        result = response.json()
        
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            print_username_summary(result)
        
        return result
        
    except requests.exceptions.RequestException as e:
        console.print(f"[red]API Error: {e}[/red]")
        sys.exit(1)


def quick_scan(args):
    """Quick scan - auto-detect type."""
    console.print(f"[cyan]Running quick scan on: {args.value}[/cyan]")
    
    try:
        response = requests.post(
            f"{args.api_url}/api/v1/scan/quick",
            headers=get_headers(),
            json={'value': args.value},
            timeout=120
        )
        response.raise_for_status()
        result = response.json()
        
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            console.print(f"[green]Detected type: {result.get('detected_type', 'unknown')}[/green]")
            console.print(f"[cyan]Risk Score: {result.get('risk_score', 0)}/100[/cyan]")
        
        return result
        
    except requests.exceptions.RequestException as e:
        console.print(f"[red]API Error: {e}[/red]")
        sys.exit(1)


def repo_scan(args):
    """Scan a GitHub repository."""
    console.print(f"[cyan]Cloning and scanning repository: {args.url}[/cyan]")
    
    try:
        response = requests.post(
            f"{args.api_url}/api/v1/scan/repo/",
            headers=get_headers(),
            json={
                'repo_url': args.url,
                'mode': args.mode
            },
            timeout=300
        )
        response.raise_for_status()
        result = response.json()
        
        if args.output == 'json':
            print(json.dumps(result, indent=2))
        else:
            console.print(f"[green]Scan completed![/green]")
            console.print(f"Status: {result.get('status', 'unknown')}")
            console.print(f"Files scanned: {result.get('files_scanned', 0)}")
            
            findings = result.get('findings', [])
            if findings:
                console.print(f"\n[red]Found {len(findings)} vulnerabilities:[/red]")
                for f in findings[:10]:
                    console.print(f"  [{f.get('severity')}] {f.get('type')} in {f.get('file')}")
            else:
                console.print("[green]No vulnerabilities found![/green]")
        
        return result
        
    except requests.exceptions.RequestException as e:
        console.print(f"[red]API Error: {e}[/red]")
        sys.exit(1)


def github_auth(args):
    """GitHub OAuth - login or link account."""
    client_id = os.environ.get('GITHUB_CLIENT_ID')
    client_secret = os.environ.get('GITHUB_CLIENT_SECRET')
    
    if not client_id or not client_secret:
        console.print("[red]Error: GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set[/red]")
        console.print("[yellow]Set them with: export GITHUB_CLIENT_ID=xxx GITHUB_CLIENT_SECRET=yyy[/yellow]")
        sys.exit(1)
    
    if args.action == 'login':
        console.print("[cyan]Starting GitHub OAuth login...[/cyan]")
        console.print(f"[yellow]Visit this URL to authorize:[/yellow]")
        console.print(f"  https://github.com/login/oauth/authorize?client_id={client_id}&scope=read:user+user:email")
        console.print(f"\n[cyan]Then run:[/cyan]")
        console.print(f"  vulnrix github --action callback --code YOUR_CODE")
    
    elif args.action == 'callback':
        if not args.code:
            console.print("[red]Error: --code required for callback[/red]")
            sys.exit(1)
        
        console.print("[cyan]Exchanging code for token...[/cyan]")
        
        token_response = requests.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": args.code,
            },
            timeout=10
        )
        
        if token_response.status_code != 200:
            console.print(f"[red]Token exchange failed: {token_response.text}[/red]")
            sys.exit(1)
        
        token_data = token_response.json()
        access_token = token_data.get('access_token')
        
        if not access_token:
            console.print("[red]No access token received[/red]")
            sys.exit(1)
        
        console.print(f"[green]Authenticated successfully![/green]")
        console.print(f"[yellow]Access token: {access_token[:10]}...[/yellow]")
        console.print("[cyan]Use this token with the API for authenticated requests.[/cyan]")
        
        if args.save_token:
            with open('.github_token', 'w') as f:
                f.write(access_token)
            console.print("[green]Token saved to .github_token[/green]")
    
    elif args.action == 'link':
        console.print("[cyan]Linking GitHub account...[/cyan]")
        console.print(f"[yellow]Visit:[/yellow]")
        console.print(f"  https://github.com/login/oauth/authorize?client_id={client_id}&scope=read:user+user:email+repo")
        console.print(f"\n[cyan]Then run:[/cyan]")
        console.print(f"  vulnrix github --action callback --code YOUR_CODE --save-token")


def release(args):
    """Release: update version in README and push to git."""
    version = args.version
    message = args.message or f"Release v{version}"
    
    console.print(f"[cyan]Preparing release v{version}...[/cyan]")
    
    readme_path = Path("README.md")
    if not readme_path.exists():
        console.print("[red]README.md not found![/red]")
        sys.exit(1)
    
    console.print("[green]Updating README.md...[/green]")
    readme_content = readme_path.read_text(encoding='utf-8')
    
    version_pattern = r'v?\d+\.\d+\.\d+'
    import re
    readme_content = re.sub(version_pattern, f'v{version}', readme_content)
    
    if '## Release' not in readme_content:
        readme_content += f"""

---

## Release v{version}

### Changelog
- {message}

"""
    
    readme_path.write_text(readme_content, encoding='utf-8')
    console.print(f"[green]Version updated to v{version}[/green]")
    
    if not args.dry_run:
        console.print("[cyan]Staging changes...[/cyan]")
        subprocess.run(['git', 'add', 'README.md'], check=True)
        
        console.print("[cyan]Creating commit...[/cyan]")
        subprocess.run(['git', 'commit', '-m', f'Release v{version}: {message}'], check=True)
        
        console.print("[cyan]Pushing to remote...[/cyan]")
        subprocess.run(['git', 'push'], check=True)
        
        console.print(f"[green]Successfully released v{version}![/green]")
    else:
        console.print(f"[yellow]Dry run - nothing committed[/yellow]")


def print_osint_summary(result):
    """Print formatted OSINT results."""
    console.print("\n" + "="*60)
    console.print("[bold]OSINT Scan Results[/bold]")
    console.print("="*60)
    console.print(f"Risk Score: {result.get('risk_score', 0)}/100")
    
    findings = result.get('findings', {})
    
    if 'email' in findings:
        breaches = findings['email'].get('breaches', {})
        console.print(f"\n[bold]Email Analysis:[/bold]")
        console.print(f"  Breaches found: {len(breaches.get('breaches', []))}")
    
    if 'username' in findings:
        console.print(f"\n[bold]Username Analysis:[/bold]")
        social = findings['username'].get('social_media', {})
        console.print(f"  Social accounts found: {len(social)}")
    
    console.print("\n" + "="*60)


def print_code_summary(result):
    """Print formatted code scan results."""
    console.print("\n" + "="*60)
    console.print("[bold]Code Scan Results[/bold]")
    console.print("="*60)
    console.print(f"Status: {result['status']}")
    console.print(f"Files scanned: {result['files_scanned']}")
    console.print(f"\nFindings:")
    console.print(f"  [red]Critical:[/red] {result['summary']['critical']}")
    console.print(f"  [red]High:[/red]     {result['summary']['high']}")
    console.print(f"  [yellow]Medium:[/yellow]   {result['summary']['medium']}")
    console.print(f"  [blue]Low:[/blue]      {result['summary']['low']}")
    
    if result['findings']:
        console.print("\n[bold]Top Findings:[/bold]")
        for finding in result['findings'][:5]:
            sev = finding.get('severity', 'Unknown')
            console.print(f"  [{sev}] {finding.get('type', 'Unknown')} in {finding.get('file', 'unknown')}:{finding.get('line', 0)}")
    
    console.print("="*60)


def print_phone_summary(result):
    """Print phone scan results."""
    console.print("\n[bold]Phone Scan Results[/bold]")
    if result.get('valid'):
        console.print(f"[green]Valid: Yes[/green]")
        console.print(f"Carrier: {result.get('carrier', 'Unknown')}")
        console.print(f"Location: {result.get('location', 'Unknown')}")
    else:
        console.print("[yellow]Could not validate phone number[/yellow]")


def print_domain_summary(result):
    """Print domain scan results."""
    console.print("\n[bold]Domain Scan Results[/bold]")
    console.print(f"Registrar: {result.get('registrar', 'Unknown')}")
    console.print(f"Created: {result.get('creation_date', 'Unknown')}")
    if result.get('dns_records'):
        console.print(f"DNS Records: {len(result['dns_records'])} found")


def print_ip_summary(result):
    """Print IP scan results."""
    console.print("\n[bold]IP Scan Results[/bold]")
    console.print(f"ASN: {result.get('asn', 'Unknown')}")
    console.print(f"Country: {result.get('country', 'Unknown')}")
    console.print(f"ISP: {result.get('isp', 'Unknown')}")


def print_username_summary(result):
    """Print username scan results."""
    console.print("\n[bold]Username Scan Results[/bold]")
    accounts = result.get('accounts', [])
    if accounts:
        table = Table(title="Found Accounts")
        table.add_column("Platform")
        table.add_column("URL")
        for acc in accounts:
            table.add_row(acc.get('platform', 'Unknown'), acc.get('url', 'N/A'))
        console.print(table)
    else:
        console.print("[yellow]No accounts found[/yellow]")


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
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--api-url', default=DEFAULT_API_URL, help='VULNRIX API URL')
    parser.add_argument('--output', '-o', choices=['text', 'json', 'sarif'], default='text', help='Output format')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # OSINT
    osint_parser = subparsers.add_parser('osint', help='OSINT scan (email, name, username, domain)')
    osint_parser.add_argument('--email', '-e', help='Email to scan')
    osint_parser.add_argument('--name', '-n', help='Name to scan')
    osint_parser.add_argument('--username', '-u', help='Username to scan')
    osint_parser.add_argument('--domain', '-d', help='Domain to scan')
    osint_parser.add_argument('--no-darkweb', action='store_true', help='Skip dark web scan')
    osint_parser.add_argument('--no-social', action='store_true', help='Skip social media scan')
    
    # Code scan
    code_parser = subparsers.add_parser('code', help='Code vulnerability scan')
    code_parser.add_argument('--path', '-p', default='.', help='Path to scan')
    code_parser.add_argument('--mode', '-m', choices=['fast', 'hybrid', 'deep'], default='hybrid', help='Scan mode')
    code_parser.add_argument('--fail-on', choices=['critical', 'high', 'medium', 'low'], help='Fail on severity')
    
    # Breach
    breach_parser = subparsers.add_parser('breach', help='Check for breaches')
    breach_parser.add_argument('--value', '-v', required=True, help='Value to check (email or password)')
    
    # Phone
    phone_parser = subparsers.add_parser('phone', help='Scan phone number')
    phone_parser.add_argument('--number', '-n', required=True, help='Phone number to scan')
    
    # Domain
    domain_parser = subparsers.add_parser('domain', help='Scan domain')
    domain_parser.add_argument('--name', '-n', required=True, help='Domain to scan')
    
    # IP
    ip_parser = subparsers.add_parser('ip', help='Scan IP address')
    ip_parser.add_argument('--address', '-a', required=True, help='IP address to scan')
    
    # Username
    username_parser = subparsers.add_parser('username', help='Scan username across social media')
    username_parser.add_argument('--handle', '-u', required=True, help='Username to scan')
    
    # Quick scan
    quick_parser = subparsers.add_parser('quick', help='Quick scan - auto-detect type')
    quick_parser.add_argument('--value', '-v', required=True, help='Value to scan')
    
    # Release
    release_parser = subparsers.add_parser('release', help='Release: update README version and push')
    release_parser.add_argument('--version', '-v', required=True, help='Version number (e.g., 1.0.0)')
    release_parser.add_argument('--message', '-m', help='Release message')
    release_parser.add_argument('--dry-run', action='store_true', help='Show what would be done without pushing')
    
    # Repo scan
    repo_parser = subparsers.add_parser('repo', help='Scan a GitHub repository')
    repo_parser.add_argument('--url', '-u', required=True, help='Repository URL (e.g., https://github.com/user/repo)')
    repo_parser.add_argument('--mode', '-m', choices=['fast', 'hybrid', 'deep'], default='hybrid', help='Scan mode')
    
    # GitHub OAuth
    github_parser = subparsers.add_parser('github', help='GitHub OAuth authentication')
    github_parser.add_argument('--action', '-a', choices=['login', 'callback', 'link'], required=True, help='OAuth action')
    github_parser.add_argument('--code', '-c', help='Authorization code (for callback)')
    github_parser.add_argument('--save-token', action='store_true', help='Save token to file')
    
    # Version
    parser.add_argument('--version', action='version', version='VULNRIX CLI 2.0.0')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        console.print("\n[bold]Examples:[/bold]")
        console.print("  vulnrix osint --email user@example.com")
        console.print("  vulnrix code --path ./src --mode deep")
        console.print("  vulnrix breach --value password123")
        console.print("  vulnrix phone --number +1234567890")
        console.print("  vulnrix domain --name example.com")
        console.print("  vulnrix ip --address 1.2.3.4")
        console.print("  vulnrix username --handle johndoe")
        console.print("  vulnrix quick --value user@example.com")
        console.print("  vulnrix repo --url https://github.com/user/repo")
        console.print("  vulnrix github --action login")
        console.print("  vulnrix release --version 1.0.0 --message 'New features'")
        sys.exit(0)
    
    if args.command == 'osint':
        osint_scan(args)
    elif args.command == 'code':
        code_scan(args)
    elif args.command == 'breach':
        breach_check(args)
    elif args.command == 'phone':
        phone_scan(args)
    elif args.command == 'domain':
        domain_scan(args)
    elif args.command == 'ip':
        ip_scan(args)
    elif args.command == 'username':
        username_scan(args)
    elif args.command == 'quick':
        quick_scan(args)
    elif args.command == 'release':
        release(args)
    elif args.command == 'repo':
        repo_scan(args)
    elif args.command == 'github':
        github_auth(args)


if __name__ == '__main__':
    main()
