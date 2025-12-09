"""
Django URLs for vuln_scan distributed node server.
"""

from django.urls import path
from . import views

app_name = "vuln_scan_nodes"
urlpatterns = [
    path("health/", views.health, name="health"),
    path("scan/", views.scan, name="scan"),
]
