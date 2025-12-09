"""
URL configuration for digitalshield project.
"""
from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse

def health_check(request):
    return HttpResponse("OK")

urlpatterns = [
    path('health/', health_check),
    path('admin/', admin.site.urls),
    path('', include('scanner.urls')),
    path('accounts/', include('accounts.urls')),
    path('vuln/', include('vuln_scan.web_dashboard.urls')),
    path('vuln-node/', include('vuln_scan.nodes.urls')),
    # REST API v1
    path('api/v1/', include('scanner.api.urls')),
]
