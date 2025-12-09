"""
Snyk API Service for code vulnerability scanning.
Provides static code analysis and dependency vulnerability detection.
"""

import os
import logging
import requests
from typing import Dict, Any, Optional, List

logger = logging.getLogger('vulnrix.services.snyk')


class SnykService:
    """
    Snyk API integration for code vulnerability analysis.
    Supports:
    - Static Application Security Testing (SAST)
    - Software Composition Analysis (SCA)
    - Container security scanning
    """
    
    BASE_URL = "https://api.snyk.io/rest"
    V1_URL = "https://api.snyk.io/v1"
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('SNYK_API_KEY')
        self.headers = {
            'Authorization': f'token {self.api_key}',
            'Content-Type': 'application/json'
        }
        self._org_id = None
    
    def is_configured(self) -> bool:
        """Check if Snyk API is configured."""
        return bool(self.api_key)
    
    def test_connection(self) -> Dict[str, Any]:
        """Test API connection and get user info."""
        if not self.is_configured():
            return {'success': False, 'error': 'API key not configured'}
        
        try:
            response = requests.get(
                f'{self.V1_URL}/user/me',
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return {
                    'success': True,
                    'user': data.get('username'),
                    'email': data.get('email'),
                    'orgs': [org.get('name') for org in data.get('orgs', [])]
                }
            else:
                return {'success': False, 'error': f'API error: {response.status_code}'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_org_id(self) -> Optional[str]:
        """Get the first organization ID for the user."""
        if self._org_id:
            return self._org_id
        
        try:
            response = requests.get(
                f'{self.V1_URL}/orgs',
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                orgs = response.json().get('orgs', [])
                if orgs:
                    self._org_id = orgs[0].get('id')
                    return self._org_id
        except Exception as e:
            logger.error(f"Failed to get org ID: {e}")
        
        return None
    
    def analyze_code(self, code: str, language: str, filename: str = "code.py") -> Dict[str, Any]:
        """
        Analyze code snippet for vulnerabilities using Snyk Code.
        
        Args:
            code: Source code to analyze
            language: Programming language (python, javascript, java, etc.)
            filename: Virtual filename for the code
            
        Returns:
            Analysis results with vulnerabilities found
        """
        if not self.is_configured():
            return self._local_analysis(code, language, filename)
        
        org_id = self.get_org_id()
        if not org_id:
            logger.warning("No Snyk org ID, falling back to local analysis")
            return self._local_analysis(code, language, filename)
        
        try:
            # Snyk Code API endpoint
            url = f'{self.BASE_URL}/orgs/{org_id}/code/tests'
            
            payload = {
                'data': {
                    'type': 'code_test',
                    'attributes': {
                        'files': [{
                            'path': filename,
                            'content': code
                        }]
                    }
                }
            }
            
            response = requests.post(
                url,
                headers={**self.headers, 'Content-Type': 'application/vnd.api+json'},
                json=payload,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                return self._parse_snyk_results(response.json())
            else:
                logger.warning(f"Snyk API returned {response.status_code}, using local analysis")
                return self._local_analysis(code, language, filename)
                
        except Exception as e:
            logger.error(f"Snyk analysis failed: {e}")
            return self._local_analysis(code, language, filename)
    
    def _parse_snyk_results(self, data: Dict) -> Dict[str, Any]:
        """Parse Snyk API response into standardized format."""
        vulnerabilities = []
        
        issues = data.get('data', {}).get('attributes', {}).get('issues', [])
        
        for issue in issues:
            vuln = {
                'type': issue.get('title', 'Security Issue'),
                'severity': issue.get('severity', 'medium').upper(),
                'cwe': issue.get('cwe', ''),
                'description': issue.get('description', ''),
                'location': {
                    'file': issue.get('filePath', ''),
                    'line': issue.get('startLine', 0),
                    'code': issue.get('snippet', '')
                },
                'recommendation': issue.get('remediation', ''),
                'source': 'snyk'
            }
            vulnerabilities.append(vuln)
        
        # Calculate summary
        summary = {
            'total': len(vulnerabilities),
            'critical': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
            'high': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
            'medium': sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM'),
            'low': sum(1 for v in vulnerabilities if v['severity'] == 'LOW')
        }
        
        return {
            'source': 'snyk_api',
            'status': 'VULNERABLE' if vulnerabilities else 'SAFE',
            'findings': vulnerabilities,
            'summary': summary
        }
    
    def _local_analysis(self, code: str, language: str, filename: str) -> Dict[str, Any]:
        """
        Fallback local analysis when Snyk API is unavailable.
        Uses pattern matching for common vulnerabilities.
        """
        vulnerabilities = []
        lines = code.split('\n')
        
        # Language-specific patterns
        patterns = self._get_patterns_for_language(language)
        
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if pattern['regex'].search(line):
                    vulnerabilities.append({
                        'type': pattern['type'],
                        'severity': pattern['severity'],
                        'cwe': pattern.get('cwe', ''),
                        'description': pattern['description'],
                        'location': {
                            'file': filename,
                            'line': i,
                            'code': line.strip()
                        },
                        'recommendation': pattern.get('recommendation', ''),
                        'source': 'local_analysis'
                    })
        
        summary = {
            'total': len(vulnerabilities),
            'critical': sum(1 for v in vulnerabilities if v['severity'] == 'CRITICAL'),
            'high': sum(1 for v in vulnerabilities if v['severity'] == 'HIGH'),
            'medium': sum(1 for v in vulnerabilities if v['severity'] == 'MEDIUM'),
            'low': sum(1 for v in vulnerabilities if v['severity'] == 'LOW')
        }
        
        return {
            'source': 'local_fallback',
            'status': 'VULNERABLE' if vulnerabilities else 'SAFE',
            'findings': vulnerabilities,
            'summary': summary,
            'note': 'Local analysis only - Snyk API unavailable'
        }
    
    def _get_patterns_for_language(self, language: str) -> List[Dict]:
        """Get vulnerability patterns for a specific language."""
        import re
        
        common_patterns = [
            {
                'regex': re.compile(r'password\s*=\s*["\'][^"\']+["\']', re.I),
                'type': 'Hardcoded Password',
                'severity': 'HIGH',
                'cwe': 'CWE-798',
                'description': 'Hardcoded password detected',
                'recommendation': 'Use environment variables or secure vault'
            },
            {
                'regex': re.compile(r'api[_-]?key\s*=\s*["\'][^"\']+["\']', re.I),
                'type': 'Hardcoded API Key',
                'severity': 'HIGH',
                'cwe': 'CWE-798',
                'description': 'Hardcoded API key detected',
                'recommendation': 'Use environment variables'
            },
            {
                'regex': re.compile(r'secret\s*=\s*["\'][^"\']+["\']', re.I),
                'type': 'Hardcoded Secret',
                'severity': 'HIGH',
                'cwe': 'CWE-798',
                'description': 'Hardcoded secret detected',
                'recommendation': 'Use secure secret management'
            }
        ]
        
        python_patterns = [
            {
                'regex': re.compile(r'eval\s*\('),
                'type': 'Code Injection',
                'severity': 'CRITICAL',
                'cwe': 'CWE-94',
                'description': 'Use of eval() can lead to code injection',
                'recommendation': 'Avoid eval(), use ast.literal_eval() for safe parsing'
            },
            {
                'regex': re.compile(r'exec\s*\('),
                'type': 'Code Injection',
                'severity': 'CRITICAL',
                'cwe': 'CWE-94',
                'description': 'Use of exec() can lead to code injection',
                'recommendation': 'Avoid exec(), use safer alternatives'
            },
            {
                'regex': re.compile(r'subprocess\..*shell\s*=\s*True'),
                'type': 'Command Injection',
                'severity': 'HIGH',
                'cwe': 'CWE-78',
                'description': 'Shell=True in subprocess can lead to command injection',
                'recommendation': 'Use shell=False and pass arguments as list'
            },
            {
                'regex': re.compile(r'pickle\.load'),
                'type': 'Insecure Deserialization',
                'severity': 'HIGH',
                'cwe': 'CWE-502',
                'description': 'Pickle deserialization can execute arbitrary code',
                'recommendation': 'Use JSON or other safe serialization formats'
            }
        ]
        
        js_patterns = [
            {
                'regex': re.compile(r'eval\s*\('),
                'type': 'Code Injection',
                'severity': 'CRITICAL',
                'cwe': 'CWE-94',
                'description': 'Use of eval() can lead to code injection',
                'recommendation': 'Avoid eval(), use JSON.parse() for data'
            },
            {
                'regex': re.compile(r'innerHTML\s*='),
                'type': 'XSS Vulnerability',
                'severity': 'HIGH',
                'cwe': 'CWE-79',
                'description': 'Direct innerHTML assignment can lead to XSS',
                'recommendation': 'Use textContent or sanitize input'
            },
            {
                'regex': re.compile(r'document\.write\s*\('),
                'type': 'XSS Vulnerability',
                'severity': 'HIGH',
                'cwe': 'CWE-79',
                'description': 'document.write can lead to XSS',
                'recommendation': 'Use DOM manipulation methods instead'
            }
        ]
        
        sql_patterns = [
            {
                'regex': re.compile(r'["\'].*\+.*["\'].*SELECT|INSERT|UPDATE|DELETE', re.I),
                'type': 'SQL Injection',
                'severity': 'CRITICAL',
                'cwe': 'CWE-89',
                'description': 'String concatenation in SQL query',
                'recommendation': 'Use parameterized queries'
            }
        ]
        
        # Return patterns based on language
        lang_lower = language.lower()
        if lang_lower in ['python', 'py']:
            return common_patterns + python_patterns
        elif lang_lower in ['javascript', 'js', 'typescript', 'ts']:
            return common_patterns + js_patterns
        elif lang_lower in ['sql']:
            return common_patterns + sql_patterns
        else:
            return common_patterns


# Singleton instance
_snyk_service = None

def get_snyk_service() -> SnykService:
    """Get or create Snyk service instance."""
    global _snyk_service
    if _snyk_service is None:
        _snyk_service = SnykService()
    return _snyk_service
