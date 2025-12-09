"""
Django URLs for vuln_scan web dashboard.
"""

from django.urls import path
from . import views

app_name = "vuln_scan"
urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("virustotal/", views.virustotal_scan, name="virustotal"),
    path("history/<int:scan_id>/", views.get_scan_result, name="scan_result"),
]
