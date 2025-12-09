"""
Continuous Monitoring Service for VULNRIX.
Provides scheduled scans and real-time alerts for security changes.
"""

from typing import Dict, List, Optional
from django.conf import settings
from django.core.mail import send_mail
import json
import logging
import hashlib
from datetime import datetime, timedelta

logger = logging.getLogger('vulnrix.monitoring')


class MonitoringService:
    """
    Manages continuous monitoring for users.
    Compares current scan results with previous to detect new threats.
    """
    
    def __init__(self, user, targets: Dict = None, interval_hours: int = 24):
        self.user = user
        self.targets = targets or {}
        self.interval_hours = interval_hours
    
    def get_monitoring_id(self) -> str:
        """Generate unique ID for this monitoring configuration."""
        data = json.dumps({
            'user_id': self.user.id,
            'targets': self.targets
        }, sort_keys=True)
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def get_last_result(self) -> Optional[Dict]:
        """Get the last scan result for comparison."""
        try:
            from scanner.models import ScanHistory
            last_scan = ScanHistory.objects.filter(
                user=self.user
            ).order_by('-created_at').first()
            
            if last_scan and hasattr(last_scan, 'results'):
                return {
                    'scan_id': last_scan.id,
                    'created_at': last_scan.created_at.isoformat(),
                    'risk_score': last_scan.risk_score,
                    'results': last_scan.results
                }
        except Exception as e:
            logger.error(f"Error getting last result: {e}")
        
        return None
    
    def run_scan(self) -> Dict:
        """Run a full OSINT scan on the configured targets."""
        from scanner.services.search_engine import SearchEngine
        from scanner.services.social_scan import SocialScanner
        from scanner.services.darkweb_scan import DarkWebScanner
        from scanner.services.multi_api_service import EmailScanService
        from scanner.services.risk_analyzer import RiskAnalyzer
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'targets': self.targets,
            'findings': {}
        }
        
        try:
            # Email scan
            if self.targets.get('email'):
                email_scanner = EmailScanService()
                breach_data = email_scanner.scan(self.targets['email'])
                results['findings']['email'] = breach_data
            
            # Name search
            if self.targets.get('name'):
                search_engine = SearchEngine()
                name_results = search_engine.search(self.targets['name'])
                results['findings']['name'] = {
                    'mentions': name_results,
                    'count': len(name_results)
                }
            
            # Username scan
            if self.targets.get('username'):
                search_engine = SearchEngine()
                social_scanner = SocialScanner()
                
                results['findings']['username'] = {
                    'mentions': search_engine.search(f'"{self.targets["username"]}"'),
                    'social': social_scanner.scan(self.targets['username'])
                }
            
            # Dark web scan
            if self.targets.get('email'):
                darkweb_scanner = DarkWebScanner()
                darkweb_data = darkweb_scanner.scan(email=self.targets.get('email'))
                results['findings']['darkweb'] = darkweb_data
            
            # Calculate risk score
            risk_analyzer = RiskAnalyzer()
            risk_result = risk_analyzer.calculate_risk_score(
                search_results=results['findings'].get('name', {}),
                breach_data=results['findings'].get('email', {}),
                has_name=bool(self.targets.get('name')),
                has_email=bool(self.targets.get('email')),
                has_username=bool(self.targets.get('username')),
                name=self.targets.get('name')
            )
            
            results['risk_score'] = risk_result['score']
            results['status'] = 'completed'
            
        except Exception as e:
            logger.error(f"Monitoring scan error: {e}")
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def calculate_diff(self, previous: Dict, current: Dict) -> Dict:
        """Calculate the difference between two scan results."""
        diff = {
            'new_breaches': [],
            'new_mentions': [],
            'new_social_accounts': [],
            'new_vulnerabilities': [],
            'risk_score_change': 0,
            'is_significant': False
        }
        
        if not previous:
            return diff
        
        # Compare breach data
        prev_breaches = set()
        curr_breaches = set()
        
        prev_email = previous.get('results', {}).get('email', {})
        curr_email = current.get('findings', {}).get('email', {})
        
        if isinstance(prev_email, dict):
            for breach in prev_email.get('breaches', []):
                prev_breaches.add(breach.get('Name', ''))
        
        if isinstance(curr_email, dict):
            for breach in curr_email.get('breaches', []):
                name = breach.get('Name', '')
                curr_breaches.add(name)
                if name not in prev_breaches:
                    diff['new_breaches'].append(breach)
        
        # Compare risk scores
        prev_risk = previous.get('risk_score', 0)
        curr_risk = current.get('risk_score', 0)
        diff['risk_score_change'] = curr_risk - prev_risk
        
        # Determine if changes are significant
        if diff['new_breaches'] or diff['risk_score_change'] >= 10:
            diff['is_significant'] = True
        
        return diff
    
    def send_alert(self, diff: Dict, current_result: Dict):
        """Send alerts for significant changes."""
        if not diff['is_significant']:
            return
        
        # Email alert
        if self.user.email:
            self._send_email_alert(diff, current_result)
        
        # Slack alert (if configured)
        try:
            if hasattr(self.user, 'profile') and self.user.profile.slack_webhook:
                self._send_slack_alert(diff, current_result)
        except Exception as e:
            logger.error(f"Slack alert error: {e}")
    
    def _send_email_alert(self, diff: Dict, current_result: Dict):
        """Send email alert."""
        try:
            breaches_count = len(diff.get('new_breaches', []))
            breach_names = ', '.join([b.get('Name', 'Unknown') for b in diff.get('new_breaches', [])])
            
            subject = f"🚨 VULNRIX Alert: {breaches_count} new exposure(s) detected"
            
            message = f"""
VULNRIX Security Alert
======================

New security exposures have been detected in your monitoring scan.

Summary:
- New breaches: {breaches_count}
- Risk score change: {diff.get('risk_score_change', 0):+d}
- Current risk score: {current_result.get('risk_score', 0)}

{'Affected breaches: ' + breach_names if breach_names else ''}

View full details at: https://vulnrix.com/dashboard

---
This is an automated message from VULNRIX Continuous Monitoring.
To adjust your notification preferences, visit your account settings.
"""
            
            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL if hasattr(settings, 'DEFAULT_FROM_EMAIL') else 'alerts@vulnrix.com',
                recipient_list=[self.user.email],
                fail_silently=True
            )
            
            logger.info(f"Email alert sent to {self.user.email}")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    
    def _send_slack_alert(self, diff: Dict, current_result: Dict):
        """Send Slack alert."""
        import requests
        
        try:
            webhook_url = self.user.profile.slack_webhook
            breaches_count = len(diff.get('new_breaches', []))
            
            payload = {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🚨 {breaches_count} new security exposure(s) detected"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*VULNRIX Monitoring Alert*\n\n"
                                   f"• New breaches: {breaches_count}\n"
                                   f"• Risk score change: {diff.get('risk_score_change', 0):+d}\n"
                                   f"• Current risk score: {current_result.get('risk_score', 0)}"
                        }
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {"type": "plain_text", "text": "View Details"},
                                "url": "https://vulnrix.com/dashboard",
                                "style": "primary"
                            }
                        ]
                    }
                ]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            logger.info("Slack alert sent successfully")
            
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
    
    def run_scheduled_scan(self) -> Dict:
        """
        Run a scheduled scan and send alerts if needed.
        This is the main entry point for Celery tasks.
        """
        logger.info(f"Running scheduled scan for user {self.user.username}")
        
        # Get previous result
        previous = self.get_last_result()
        
        # Run current scan
        current = self.run_scan()
        
        # Calculate difference
        diff = self.calculate_diff(previous, current)
        
        # Send alerts if significant changes
        if diff['is_significant']:
            self.send_alert(diff, current)
            logger.info(f"Alert sent for user {self.user.username}: {len(diff['new_breaches'])} new breaches")
        else:
            logger.info(f"No significant changes for user {self.user.username}")
        
        return {
            'status': 'completed',
            'diff': diff,
            'current_risk_score': current.get('risk_score', 0),
            'alert_sent': diff['is_significant']
        }


# Celery task (if Celery is installed)
try:
    from celery import shared_task
    
    @shared_task
    def run_user_monitoring(user_id: int, targets: Dict, interval_hours: int = 24):
        """Celery task to run scheduled monitoring for a user."""
        from django.contrib.auth.models import User
        
        try:
            user = User.objects.get(id=user_id)
            service = MonitoringService(user, targets, interval_hours)
            return service.run_scheduled_scan()
        except User.DoesNotExist:
            logger.error(f"User {user_id} not found for monitoring")
            return {'status': 'error', 'error': 'User not found'}
        except Exception as e:
            logger.error(f"Monitoring task error: {e}")
            return {'status': 'error', 'error': str(e)}
    
    @shared_task
    def check_all_monitoring():
        """Run monitoring for all users with monitoring enabled."""
        from accounts.models import UserProfile
        
        profiles = UserProfile.objects.filter(monitoring_enabled=True)
        results = []
        
        for profile in profiles:
            try:
                targets = json.loads(profile.monitoring_targets_json or '{}')
                if targets:
                    result = run_user_monitoring.delay(
                        profile.user.id,
                        targets,
                        profile.monitoring_interval_hours
                    )
                    results.append({'user_id': profile.user.id, 'task_id': result.id})
            except Exception as e:
                logger.error(f"Error queuing monitoring for user {profile.user.id}: {e}")
        
        return {'queued': len(results), 'tasks': results}

except ImportError:
    # Celery not installed, provide sync alternatives
    def run_user_monitoring(user_id: int, targets: Dict, interval_hours: int = 24):
        """Sync version of monitoring task."""
        from django.contrib.auth.models import User
        
        user = User.objects.get(id=user_id)
        service = MonitoringService(user, targets, interval_hours)
        return service.run_scheduled_scan()
