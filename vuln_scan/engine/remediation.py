"""
AI-Powered Auto-Remediation Engine for VULNRIX.
Generates secure code fixes for detected vulnerabilities.
"""

from typing import Dict, List, Optional
import os
import difflib


class RemediationEngine:
    """
    Generates secure code fixes for vulnerabilities using LLM.
    """
    
    # Common fix patterns for known vulnerability types
    FIX_PATTERNS = {
        'SQL Injection': {
            'pattern': r'execute\s*\([^)]*\+',
            'fix_hint': 'Use parameterized queries instead of string concatenation',
            'example_fix': '''
# Vulnerable:
cursor.execute("SELECT * FROM users WHERE id=" + user_id)

# Fixed:
cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
'''
        },
        'XSS': {
            'pattern': r'innerHTML\s*=|\.html\s*\(',
            'fix_hint': 'Use textContent or proper HTML escaping',
            'example_fix': '''
# Vulnerable:
element.innerHTML = userInput;

# Fixed:
element.textContent = userInput;
// Or with escaping:
element.innerHTML = escapeHtml(userInput);
'''
        },
        'Command Injection': {
            'pattern': r'os\.system|subprocess\.call\s*\([^)]*\+|shell=True',
            'fix_hint': 'Use subprocess with argument list, avoid shell=True',
            'example_fix': '''
# Vulnerable:
os.system("ping " + host)

# Fixed:
subprocess.run(["ping", host], shell=False)
'''
        },
        'Path Traversal': {
            'pattern': r'open\s*\([^)]*\+',
            'fix_hint': 'Validate path against allowed directories',
            'example_fix': '''
# Vulnerable:
open("/files/" + filename)

# Fixed:
import os
safe_path = os.path.normpath(os.path.join("/files/", filename))
if not safe_path.startswith("/files/"):
    raise ValueError("Invalid path")
open(safe_path)
'''
        },
        'Hardcoded Secret': {
            'pattern': r'password\s*=\s*["\'][^"\']+["\']',
            'fix_hint': 'Use environment variables or secrets manager',
            'example_fix': '''
# Vulnerable:
password = "secret123"

# Fixed:
import os
password = os.environ.get("DB_PASSWORD")
'''
        }
    }
    
    def __init__(self, llm_provider=None):
        """Initialize with optional LLM provider."""
        self.llm = llm_provider
    
    def generate_fix(self, finding: Dict, code_context: str, 
                     surrounding_lines: int = 5) -> Dict:
        """
        Generate a fix for a vulnerability.
        
        Args:
            finding: Vulnerability finding dict with type, line, file, etc.
            code_context: The vulnerable code snippet
            surrounding_lines: Number of lines of context to include
            
        Returns:
            Dict with original code, fixed code, diff, and explanation
        """
        vuln_type = finding.get('type', '')
        cwe = finding.get('cwe', '')
        file_path = finding.get('file', '')
        line_num = finding.get('line', 0)
        
        # Try pattern-based fix first
        pattern_fix = self._get_pattern_fix(vuln_type, code_context)
        
        if pattern_fix:
            return {
                'status': 'generated',
                'method': 'pattern',
                'original': code_context,
                'fixed': pattern_fix['fixed'],
                'diff': self._generate_diff(code_context, pattern_fix['fixed']),
                'explanation': pattern_fix['hint'],
                'example': pattern_fix.get('example', ''),
                'confidence': 0.8,
                'manual_review_required': True
            }
        
        # Try LLM-based fix if available
        if self.llm:
            llm_fix = self._generate_llm_fix(finding, code_context)
            if llm_fix:
                return llm_fix
        
        # Fallback to recommendation only
        return {
            'status': 'recommendation_only',
            'method': 'manual',
            'original': code_context,
            'fixed': None,
            'diff': None,
            'explanation': finding.get('recommendation', 'Review and fix manually'),
            'cwe_link': f'https://cwe.mitre.org/data/definitions/{cwe.replace("CWE-", "")}.html' if cwe else None,
            'confidence': 0.0,
            'manual_review_required': True
        }
    
    def _get_pattern_fix(self, vuln_type: str, code: str) -> Optional[Dict]:
        """Get a fix based on known patterns."""
        for known_type, pattern_info in self.FIX_PATTERNS.items():
            if known_type.lower() in vuln_type.lower():
                return {
                    'fixed': self._apply_pattern_fix(known_type, code),
                    'hint': pattern_info['fix_hint'],
                    'example': pattern_info['example_fix']
                }
        return None
    
    def _apply_pattern_fix(self, vuln_type: str, code: str) -> str:
        """Apply a pattern-based fix to code."""
        import re
        
        if 'SQL Injection' in vuln_type:
            # Convert string concatenation to parameterized query
            # This is a simplified transformation
            fixed = re.sub(
                r'execute\s*\(\s*(["\'])(.*?)\1\s*\+\s*(\w+)\s*\)',
                r'execute(\1\2?\1, (\3,))',
                code
            )
            return fixed
        
        if 'Hardcoded Secret' in vuln_type:
            # Replace hardcoded value with env var
            fixed = re.sub(
                r'(password|secret|api_key|token)\s*=\s*["\'][^"\']+["\']',
                r'\1 = os.environ.get("\1".upper())',
                code,
                flags=re.IGNORECASE
            )
            if 'import os' not in code:
                fixed = 'import os\n' + fixed
            return fixed
        
        # Default: return original (manual fix required)
        return code
    
    def _generate_llm_fix(self, finding: Dict, code: str) -> Optional[Dict]:
        """Generate fix using LLM."""
        if not self.llm:
            return None
        
        prompt = f"""You are a security engineer. Fix this vulnerability:

VULNERABILITY: {finding.get('type')} ({finding.get('cwe', 'Unknown CWE')})
SEVERITY: {finding.get('severity', 'Unknown')}
FILE: {finding.get('file', 'unknown')}
LINE: {finding.get('line', 0)}

VULNERABLE CODE:
```
{code}
```

INSTRUCTIONS:
1. Generate ONLY the fixed code - no explanations
2. Use secure coding practices:
   - Parameterized queries for SQL
   - Proper escaping for XSS
   - Input validation for injection
   - Environment variables for secrets
3. Maintain the original code structure where possible
4. Add necessary imports if needed

FIXED CODE:
```"""
        
        try:
            fixed_code = self.llm.generate(prompt)
            # Clean up response
            fixed_code = fixed_code.strip()
            if fixed_code.startswith('```'):
                fixed_code = fixed_code.split('```')[1]
            if fixed_code.startswith('python') or fixed_code.startswith('javascript'):
                fixed_code = '\n'.join(fixed_code.split('\n')[1:])
            
            return {
                'status': 'generated',
                'method': 'llm',
                'original': code,
                'fixed': fixed_code,
                'diff': self._generate_diff(code, fixed_code),
                'explanation': f"AI-generated fix for {finding.get('type')}",
                'confidence': 0.7,
                'manual_review_required': True
            }
        except Exception as e:
            return None
    
    def _generate_diff(self, original: str, fixed: str) -> str:
        """Generate unified diff between original and fixed code."""
        original_lines = original.splitlines(keepends=True)
        fixed_lines = fixed.splitlines(keepends=True)
        
        diff = difflib.unified_diff(
            original_lines,
            fixed_lines,
            fromfile='original',
            tofile='fixed',
            lineterm=''
        )
        
        return ''.join(diff)
    
    def batch_generate_fixes(self, findings: List[Dict], 
                            code_by_file: Dict[str, str]) -> List[Dict]:
        """
        Generate fixes for multiple vulnerabilities.
        
        Args:
            findings: List of vulnerability findings
            code_by_file: Dict mapping file paths to their content
            
        Returns:
            List of fix results
        """
        results = []
        
        for finding in findings:
            file_path = finding.get('file', '')
            line_num = finding.get('line', 0)
            
            # Get code context
            code = code_by_file.get(file_path, '')
            if code:
                lines = code.split('\n')
                start = max(0, line_num - 3)
                end = min(len(lines), line_num + 3)
                context = '\n'.join(lines[start:end])
            else:
                context = finding.get('code', '')
            
            # Generate fix
            fix = self.generate_fix(finding, context)
            fix['finding'] = finding
            results.append(fix)
        
        return results


# Convenience function
def generate_fix(finding: Dict, code_context: str) -> Dict:
    """Generate a fix for a single vulnerability."""
    engine = RemediationEngine()
    return engine.generate_fix(finding, code_context)
