"""
Integrations Hub for VULNRIX.
Base classes and implementations for third-party integrations.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional
import logging
import requests

logger = logging.getLogger('vulnrix.integrations')


class IntegrationBase(ABC):
    """Base class for all integrations."""
    
    name: str = "Base Integration"
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.enabled = True
    
    @abstractmethod
    def send_finding(self, finding: Dict) -> bool:
        """Send a single finding to the integration."""
        pass
    
    @abstractmethod
    def send_report(self, report: Dict) -> bool:
        """Send a full report to the integration."""
        pass
    
    @abstractmethod
    def test_connection(self) -> bool:
        """Test the connection to the integration."""
        pass


class SlackIntegration(IntegrationBase):
    """Slack webhook integration for alerts."""
    
    name = "Slack"
    
    def __init__(self, webhook_url: str, channel: str = None):
        super().__init__()
        self.webhook_url = webhook_url
        self.channel = channel
    
    def send_finding(self, finding: Dict) -> bool:
        """Send a finding alert to Slack."""
        try:
            severity = finding.get('severity', 'Unknown').lower()
            color = {
                'critical': '#dc2626',
                'high': '#ef4444',
                'medium': '#f59e0b',
                'low': '#10b981'
            }.get(severity, '#6b7280')
            
            payload = {
                "attachments": [{
                    "color": color,
                    "blocks": [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": f"🔴 {finding.get('type', 'Vulnerability')} ({severity.upper()})"
                            }
                        },
                        {
                            "type": "section",
                            "fields": [
                                {"type": "mrkdwn", "text": f"*File:*\n`{finding.get('file', 'unknown')}`"},
                                {"type": "mrkdwn", "text": f"*Line:*\n{finding.get('line', 'N/A')}"},
                                {"type": "mrkdwn", "text": f"*CWE:*\n{finding.get('cwe', 'N/A')}"}
                            ]
                        },
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"*Description:*\n{finding.get('reason', 'No description')[:500]}"
                            }
                        },
                        {
                            "type": "actions",
                            "elements": [
                                {
                                    "type": "button",
                                    "text": {"type": "plain_text", "text": "View Details"},
                                    "url": finding.get('url', 'https://vulnrix.com/dashboard'),
                                    "style": "primary"
                                }
                            ]
                        }
                    ]
                }]
            }
            
            if self.channel:
                payload['channel'] = self.channel
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Slack send_finding error: {e}")
            return False
    
    def send_report(self, report: Dict) -> bool:
        """Send a summary report to Slack."""
        try:
            counts = report.get('severity_counts', {})
            total = sum(counts.values())
            
            payload = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "📊 VULNRIX Security Scan Complete"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Risk Score:*\n{report.get('risk_score', 0)}/100"},
                            {"type": "mrkdwn", "text": f"*Total Findings:*\n{total}"},
                            {"type": "mrkdwn", "text": f"*Critical:*\n{counts.get('critical', 0)}"},
                            {"type": "mrkdwn", "text": f"*High:*\n{counts.get('high', 0)}"},
                        ]
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "View Full Report"},
                                "url": report.get('report_url', 'https://vulnrix.com/dashboard'),
                                "style": "primary"
                            }
                        ]
                    }
                ]
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code == 200
            
        except Exception as e:
            logger.error(f"Slack send_report error: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Test Slack webhook."""
        try:
            payload = {
                "text": "🔗 VULNRIX integration test successful!"
            }
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            return response.status_code == 200
        except:
            return False


class GitHubIntegration(IntegrationBase):
    """GitHub integration for issues and PR comments."""
    
    name = "GitHub"
    
    def __init__(self, token: str, repo: str):
        super().__init__()
        self.token = token
        self.repo = repo  # format: owner/repo
        self.api_base = "https://api.github.com"
    
    def _headers(self) -> Dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json"
        }
    
    def send_finding(self, finding: Dict) -> bool:
        """Create a GitHub issue for a finding."""
        try:
            severity = finding.get('severity', 'Unknown')
            labels = ['security', f'severity:{severity.lower()}']
            
            body = f"""
## Security Vulnerability Detected

**Type:** {finding.get('type', 'Unknown')}
**Severity:** {severity}
**CWE:** {finding.get('cwe', 'N/A')}

### Location
- **File:** `{finding.get('file', 'unknown')}`
- **Line:** {finding.get('line', 'N/A')}

### Description
{finding.get('reason', 'No description provided.')}

### Vulnerable Code
```
{finding.get('code', 'N/A')}
```

### Recommendation
{finding.get('recommendation', 'Review and fix this vulnerability.')}

---
*This issue was automatically created by VULNRIX Security Scanner*
"""
            
            payload = {
                "title": f"[Security] {finding.get('type', 'Vulnerability')} in {finding.get('file', 'unknown')}",
                "body": body,
                "labels": labels
            }
            
            response = requests.post(
                f"{self.api_base}/repos/{self.repo}/issues",
                headers=self._headers(),
                json=payload,
                timeout=30
            )
            
            return response.status_code == 201
            
        except Exception as e:
            logger.error(f"GitHub send_finding error: {e}")
            return False
    
    def send_report(self, report: Dict) -> bool:
        """Create a summary issue for a scan report."""
        try:
            counts = report.get('severity_counts', {})
            
            body = f"""
## VULNRIX Security Scan Report

**Scan Date:** {report.get('timestamp', 'Unknown')}
**Risk Score:** {report.get('risk_score', 0)}/100

### Summary

| Severity | Count |
|----------|-------|
| Critical | {counts.get('critical', 0)} |
| High | {counts.get('high', 0)} |
| Medium | {counts.get('medium', 0)} |
| Low | {counts.get('low', 0)} |

### Next Steps

1. Review critical and high severity findings
2. Create fix PRs for each issue
3. Re-run scan after fixes

---
*Generated by VULNRIX Security Scanner*
"""
            
            payload = {
                "title": f"[Security Scan] {sum(counts.values())} findings detected",
                "body": body,
                "labels": ["security", "scan-report"]
            }
            
            response = requests.post(
                f"{self.api_base}/repos/{self.repo}/issues",
                headers=self._headers(),
                json=payload,
                timeout=30
            )
            
            return response.status_code == 201
            
        except Exception as e:
            logger.error(f"GitHub send_report error: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Test GitHub API access."""
        try:
            response = requests.get(
                f"{self.api_base}/repos/{self.repo}",
                headers=self._headers(),
                timeout=10
            )
            return response.status_code == 200
        except:
            return False


class JiraIntegration(IntegrationBase):
    """Jira integration for ticket creation."""
    
    name = "Jira"
    
    def __init__(self, base_url: str, email: str, api_token: str, project_key: str):
        super().__init__()
        self.base_url = base_url.rstrip('/')
        self.email = email
        self.api_token = api_token
        self.project_key = project_key
    
    def _auth(self):
        return (self.email, self.api_token)
    
    def send_finding(self, finding: Dict) -> bool:
        """Create a Jira ticket for a finding."""
        try:
            severity = finding.get('severity', 'Medium')
            priority_map = {'critical': 'Highest', 'high': 'High', 'medium': 'Medium', 'low': 'Low'}
            
            description = f"""
h2. Security Vulnerability

*Type:* {finding.get('type', 'Unknown')}
*Severity:* {severity}
*CWE:* {finding.get('cwe', 'N/A')}

h3. Location
* *File:* {finding.get('file', 'unknown')}
* *Line:* {finding.get('line', 'N/A')}

h3. Description
{finding.get('reason', 'No description provided.')}

h3. Recommendation
{finding.get('recommendation', 'Review and fix this vulnerability.')}

----
_Created by VULNRIX Security Scanner_
"""
            
            payload = {
                "fields": {
                    "project": {"key": self.project_key},
                    "summary": f"[Security] {finding.get('type', 'Vulnerability')} in {finding.get('file', 'unknown')}",
                    "description": description,
                    "issuetype": {"name": "Bug"},
                    "priority": {"name": priority_map.get(severity.lower(), 'Medium')},
                    "labels": ["security", "vulnrix"]
                }
            }
            
            response = requests.post(
                f"{self.base_url}/rest/api/3/issue",
                auth=self._auth(),
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            return response.status_code == 201
            
        except Exception as e:
            logger.error(f"Jira send_finding error: {e}")
            return False
    
    def send_report(self, report: Dict) -> bool:
        """Create a summary ticket for a scan."""
        # Similar to send_finding but with report summary
        return self.send_finding({
            'type': 'Security Scan Report',
            'severity': 'Medium',
            'file': 'N/A',
            'reason': f"Security scan completed with {sum(report.get('severity_counts', {}).values())} findings.",
            'recommendation': 'Review individual findings and prioritize remediation.'
        })
    
    def test_connection(self) -> bool:
        """Test Jira API access."""
        try:
            response = requests.get(
                f"{self.base_url}/rest/api/3/myself",
                auth=self._auth(),
                timeout=10
            )
            return response.status_code == 200
        except:
            return False


class IntegrationManager:
    """Manages all configured integrations."""
    
    def __init__(self):
        self.integrations: List[IntegrationBase] = []
    
    def add(self, integration: IntegrationBase):
        """Add an integration."""
        self.integrations.append(integration)
    
    def broadcast_finding(self, finding: Dict):
        """Send a finding to all integrations."""
        for integration in self.integrations:
            if integration.enabled:
                try:
                    integration.send_finding(finding)
                except Exception as e:
                    logger.error(f"Integration {integration.name} failed: {e}")
    
    def broadcast_report(self, report: Dict):
        """Send a report to all integrations."""
        for integration in self.integrations:
            if integration.enabled:
                try:
                    integration.send_report(report)
                except Exception as e:
                    logger.error(f"Integration {integration.name} failed: {e}")
