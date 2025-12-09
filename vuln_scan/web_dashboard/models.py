"""
Models for vuln_scan web dashboard - stores scan history.
"""
import json
from django.db import models
from django.contrib.auth.models import User


class CodeScanHistory(models.Model):
    """Stores history of code vulnerability scans."""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='code_scans')
    filename = models.CharField(max_length=255)
    language = models.CharField(max_length=50, blank=True)
    mode = models.CharField(max_length=20, default='fast')
    status = models.CharField(max_length=20)  # SAFE, VULNERABLE, ERROR
    risk_score = models.IntegerField(default=0)
    
    # Summary counts
    total_findings = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    
    # Full results as JSON
    findings_json = models.TextField(default='[]')
    full_result_json = models.TextField(default='{}')
    
    # Metadata
    scan_duration = models.FloatField(default=0.0)
    file_hash = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Code Scan'
        verbose_name_plural = 'Code Scans'
    
    def __str__(self):
        return f"{self.filename} - {self.status} ({self.created_at.strftime('%Y-%m-%d %H:%M')})"
    
    def set_findings(self, findings: list):
        """Store findings as JSON."""
        self.findings_json = json.dumps(findings)
    
    def get_findings(self) -> list:
        """Retrieve findings from JSON."""
        try:
            return json.loads(self.findings_json)
        except:
            return []
    
    def set_full_result(self, result: dict):
        """Store full result as JSON."""
        self.full_result_json = json.dumps(result)
    
    def get_full_result(self) -> dict:
        """Retrieve full result from JSON."""
        try:
            return json.loads(self.full_result_json)
        except:
            return {}
