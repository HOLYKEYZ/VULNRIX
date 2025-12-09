"""
URL configuration for digitalshield project.
"""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('scanner.urls')),
    path('accounts/', include('accounts.urls')),
    path('vuln/', include('vuln_scan.web_dashboard.urls')),
    path('vuln-node/', include('vuln_scan.nodes.urls')),
    # REST API v1
    path('api/v1/', include('scanner.api.urls')),
]

