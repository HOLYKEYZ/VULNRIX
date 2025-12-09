"""
Django app config for vuln_scan web dashboard.
"""

from django.apps import AppConfig


class VulnScanConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "vuln_scan.web_dashboard"
    label = "vuln_scan"
