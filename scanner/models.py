"""
Django models for scanner app - mirrors Flask models.
"""
from django.db import models
from django.contrib.auth.models import User
import json


class ScanHistory(models.Model):
    """Scan model to store scan requests - mirrors Flask Scan model."""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scans')
    
    # Input fields
    name = models.CharField(max_length=200, null=True, blank=True)
    email = models.CharField(max_length=200, null=True, blank=True)
    username = models.CharField(max_length=200, null=True, blank=True)
    phone = models.CharField(max_length=50, null=True, blank=True)
    domain = models.CharField(max_length=200, null=True, blank=True)
    ip = models.CharField(max_length=50, null=True, blank=True)
    social_handles_json = models.TextField(null=True, blank=True)  # JSON string of selected social platforms
    
    # Results
    risk_score = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['user', '-created_at']),
        ]
    
    @property
    def social_handles(self):
        """Get social handles as dict."""
        if self.social_handles_json:
            try:
                return json.loads(self.social_handles_json)
            except:
                return {}
        return {}
    
    @social_handles.setter
    def social_handles(self, value):
        """Set social handles as JSON string."""
        self.social_handles_json = json.dumps(value) if value else None
    
    def __str__(self):
        return f'Scan {self.id} by {self.user.username}'


class ScanResult(models.Model):
    """ScanResult model to store detailed scan results - mirrors Flask ScanResult model."""
    
    scan = models.OneToOneField(ScanHistory, on_delete=models.CASCADE, related_name='results')
    
    # JSON fields for storing various result types
    search_results_json = models.TextField(null=True, blank=True)  # Web search results
    intelx_results_json = models.TextField(null=True, blank=True)  # IntelX OSINT results
    breach_data_json = models.TextField(null=True, blank=True)  # Breach check results
    social_results_json = models.TextField(null=True, blank=True)  # Social media scan results
    phone_results_json = models.TextField(null=True, blank=True)  # Phone scan results
    ip_results_json = models.TextField(null=True, blank=True)  # IP scan results
    public_records_json = models.TextField(null=True, blank=True)  # Public records results
    email_pattern_json = models.TextField(null=True, blank=True)  # Email pattern analysis
    darkweb_scan_json = models.TextField(null=True, blank=True)  # Dark web scan results
    correlation_json = models.TextField(null=True, blank=True)  # Correlation analysis
    risk_breakdown_json = models.TextField(null=True, blank=True)  # Detailed risk breakdown
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    def get_json_field(self, field_name):
        """Helper to get JSON field as dict."""
        json_str = getattr(self, f'{field_name}_json', None)
        if json_str:
            try:
                return json.loads(json_str)
            except:
                return {}
        return {}
    
    def set_json_field(self, field_name, value):
        """Helper to set JSON field from dict."""
        setattr(self, f'{field_name}_json', json.dumps(value) if value else None)
    
    def __str__(self):
        return f'ScanResult {self.id} for Scan {self.scan.id}'
