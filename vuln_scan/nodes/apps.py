"""
Django app config for vuln_scan nodes.
"""

from django.apps import AppConfig


class VulnScanNodesConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "vuln_scan.nodes"
    label = "vuln_scan_nodes"
