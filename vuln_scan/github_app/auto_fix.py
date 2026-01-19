"""
AI-Powered Auto-Fix for VULNRIX GitHub App.
Features:
1. Review PRs for security issues and suggest fixes
2. Create PRs to fix vulnerable dependencies
"""
import os
import re
import logging
from typing import Optional, Dict, List, Tuple

logger = logging.getLogger(__name__)


def get_ai_provider():
    """Get the configured AI provider for code analysis."""
    try:
        from vuln_scan.providers import load_provider
        return load_provider('gemini')  # Use Gemini for code generation
    except Exception as e:
        logger.error(f"Failed to load AI provider: {e}")
        return None


def review_pr_for_security(diff_content: str, file_paths: List[str]) -> Dict:
    """
    Use AI to review a PR diff for security issues.
    Returns a dict with:
    - is_secure: bool
    - issues: list of found issues
    - suggestions: list of suggested fixes
    """
    provider = get_ai_provider()
    if not provider:
        return {"error": "AI provider not available", "is_secure": True, "issues": [], "suggestions": []}
    
    prompt = f"""You are a security code reviewer. Analyze this Pull Request diff for security vulnerabilities.

## Files Changed:
{', '.join(file_paths)}

## Diff Content:
```diff
{diff_content[:15000]}  # Limit to avoid token limits
```

## Task:
1. Identify any security vulnerabilities introduced by this PR
2. Focus on: SQL Injection, XSS, Command Injection, Path Traversal, Hardcoded Secrets, Insecure Dependencies
3. For each issue, provide a specific fix suggestion

## Response Format (JSON):
{{
    "is_secure": true/false,
    "issues": [
        {{
            "severity": "high/medium/low",
            "type": "SQL Injection",
            "file": "path/to/file.py",
            "line": "approximate line in diff",
            "description": "Brief description",
            "suggestion": "How to fix it"
        }}
    ],
    "overall_comment": "Summary for the PR author"
}}

Respond ONLY with valid JSON."""

    try:
        response = provider.analyze(prompt)
        # Parse JSON from response
        import json
        import json_repair
        
        # Try to extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            result = json_repair.loads(json_match.group())
            return result
        else:
            return {"is_secure": True, "issues": [], "suggestions": [], "overall_comment": response}
    except Exception as e:
        logger.error(f"AI review failed: {e}")
        return {"error": str(e), "is_secure": True, "issues": [], "suggestions": []}


def generate_dependency_fix(package_name: str, current_version: str, 
                            vulnerability: str, ecosystem: str = "pip") -> Tuple[str, str]:
    """
    Use AI to generate a fix for a vulnerable dependency.
    Returns (fixed_version, explanation).
    """
    provider = get_ai_provider()
    if not provider:
        return (current_version, "AI provider not available")
    
    prompt = f"""You are a dependency security expert.

## Vulnerability:
- Package: {package_name}
- Current Version: {current_version}
- Ecosystem: {ecosystem}
- Issue: {vulnerability}

## Task:
Recommend the MINIMUM safe version that fixes this vulnerability.
Consider backwards compatibility.

## Response Format (JSON):
{{
    "recommended_version": "X.Y.Z",
    "explanation": "Why this version is safe",
    "breaking_changes": "Any breaking changes to be aware of"
}}

Respond ONLY with valid JSON."""

    try:
        response = provider.analyze(prompt)
        import json
        import json_repair
        
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            result = json_repair.loads(json_match.group())
            return (result.get('recommended_version', current_version), 
                    result.get('explanation', 'AI recommendation'))
        else:
            return (current_version, response)
    except Exception as e:
        logger.error(f"AI fix generation failed: {e}")
        return (current_version, str(e))


def create_dependency_fix_pr(github_service, installation_id: int, 
                              owner: str, repo: str, 
                              findings: List[Dict]) -> Optional[Dict]:
    """
    Create a PR to fix vulnerable dependencies.
    
    Args:
        github_service: GitHubAppService instance
        installation_id: GitHub App installation ID
        owner: Repository owner
        repo: Repository name
        findings: List of SCA findings with package info
    
    Returns:
        PR info dict or None if failed
    """
    if not findings:
        return None
    
    # Get current requirements.txt or package.json
    # For now, focus on Python (requirements.txt)
    try:
        content = github_service.get_file_content(installation_id, owner, repo, "requirements.txt")
        if not content:
            logger.warning("No requirements.txt found")
            return None
    except Exception as e:
        logger.error(f"Failed to get requirements.txt: {e}")
        return None
    
    # Parse and fix dependencies
    updated_lines = []
    fixed_packages = []
    
    for line in content.split('\n'):
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith('#'):
            updated_lines.append(line)
            continue
        
        # Parse package==version or package>=version
        match = re.match(r'^([a-zA-Z0-9_-]+)([<>=!]+)?(.+)?$', line_stripped)
        if not match:
            updated_lines.append(line)
            continue
        
        pkg_name = match.group(1).lower()
        operator = match.group(2) or '>='
        current_version = match.group(3) or ''
        
        # Check if this package has a finding
        for finding in findings:
            if finding.get('package', '').lower() == pkg_name:
                # Get AI recommendation for fix
                fixed_version, explanation = generate_dependency_fix(
                    pkg_name, 
                    current_version,
                    finding.get('description', 'Vulnerability detected'),
                    'pip'
                )
                
                if fixed_version != current_version:
                    updated_lines.append(f"{pkg_name}>={fixed_version}")
                    fixed_packages.append({
                        'package': pkg_name,
                        'old': current_version,
                        'new': fixed_version,
                        'reason': explanation
                    })
                else:
                    updated_lines.append(line)
                break
        else:
            updated_lines.append(line)
    
    if not fixed_packages:
        logger.info("No packages to fix")
        return None
    
    # Create branch and PR
    new_content = '\n'.join(updated_lines)
    branch_name = f"vulnrix/fix-deps-{len(fixed_packages)}"
    
    # Get default branch SHA
    try:
        # Get the default branch ref
        import requests
        token = github_service.get_installation_token(installation_id)
        ref_response = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/main",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            timeout=10
        )
        if ref_response.status_code != 200:
            # Try master branch
            ref_response = requests.get(
                f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/master",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                timeout=10
            )
        
        if ref_response.status_code != 200:
            logger.error(f"Failed to get branch ref: {ref_response.text}")
            return None
        
        base_sha = ref_response.json()['object']['sha']
        base_branch = 'main' if 'main' in ref_response.url else 'master'
        
        # Get file SHA
        file_response = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/requirements.txt",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            timeout=10
        )
        if file_response.status_code != 200:
            logger.error(f"Failed to get file SHA: {file_response.text}")
            return None
        
        file_sha = file_response.json()['sha']
        
    except Exception as e:
        logger.error(f"Failed to get repo info: {e}")
        return None
    
    # Create branch
    if not github_service.create_branch(installation_id, owner, repo, branch_name, base_sha):
        logger.error("Failed to create branch")
        return None
    
    # Update file
    commit_message = f"fix: Update {len(fixed_packages)} vulnerable dependencies\n\n" + \
                     "\n".join([f"- {p['package']}: {p['old']} -> {p['new']}" for p in fixed_packages])
    
    if not github_service.update_file(installation_id, owner, repo, 
                                       "requirements.txt", new_content, 
                                       commit_message, branch_name, file_sha):
        logger.error("Failed to update file")
        return None
    
    # Create PR
    pr_body = f"""## 🔒 VULNRIX Security Fix

This PR updates vulnerable dependencies identified by VULNRIX.

### Changes:
| Package | Old Version | New Version | Reason |
|---------|-------------|-------------|--------|
""" + "\n".join([f"| {p['package']} | {p['old']} | {p['new']} | {p['reason'][:50]}... |" for p in fixed_packages])
    
    pr_body += "\n\n---\n*Automated by [VULNRIX](https://vulnrix.onrender.com)*"
    
    pr = github_service.create_pull_request(
        installation_id, owner, repo,
        title=f"🔒 Fix {len(fixed_packages)} vulnerable dependencies",
        body=pr_body,
        head=branch_name,
        base=base_branch
    )
    
    return pr


def post_pr_review_comment(github_service, installation_id: int,
                           owner: str, repo: str, pr_number: int,
                           review_result: Dict) -> bool:
    """
    Post AI security review as a PR comment.
    """
    import requests
    
    try:
        token = github_service.get_installation_token(installation_id)
        
        # Build comment body
        if review_result.get('is_secure', True) and not review_result.get('issues'):
            body = """## ✅ VULNRIX Security Review

No security issues detected in this PR.

---
*Automated security review by [VULNRIX](https://vulnrix.onrender.com)*"""
        else:
            issues_md = ""
            for issue in review_result.get('issues', []):
                severity_emoji = "🔴" if issue.get('severity') == 'high' else ("🟠" if issue.get('severity') == 'medium' else "🟡")
                issues_md += f"\n### {severity_emoji} {issue.get('type', 'Issue')}\n"
                issues_md += f"**File:** `{issue.get('file', 'Unknown')}`\n"
                issues_md += f"**Description:** {issue.get('description', 'N/A')}\n"
                issues_md += f"**Suggestion:** {issue.get('suggestion', 'N/A')}\n"
            
            body = f"""## 🔒 VULNRIX Security Review

{review_result.get('overall_comment', 'Security issues detected.')}

{issues_md}

---
*Automated security review by [VULNRIX](https://vulnrix.onrender.com)*"""
        
        # Post comment
        response = requests.post(
            f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json"
            },
            json={"body": body},
            timeout=10
        )
        
        return response.status_code in [200, 201]
    
    except Exception as e:
        logger.error(f"Failed to post PR comment: {e}")
        return False
