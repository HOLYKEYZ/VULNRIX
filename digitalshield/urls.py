"""
URL configuration for digitalshield project.
"""
from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse
from vuln_scan.web_dashboard.views import home, robots_txt, sitemap_xml
from scanner.views import docs

def health_check(request):
    return HttpResponse("OK")

urlpatterns = [
    path('health/', health_check),
    path('robots.txt', robots_txt),
    path('sitemap.xml', sitemap_xml),
    path('admin/', admin.site.urls),
    path('', home, name='home'),
    path('docs/', docs, name='docs'),
    
    # Dashboard Architecture Swap
    path('dashboard/', include('vuln_scan.web_dashboard.urls')), # Main Dashboard = Code Scanner
    path('dashboard/footprint/', include('scanner.urls')),       # Sub-Dashboard = OSINT
    
    path('accounts/', include('accounts.urls')),
    path('vuln-node/', include('vuln_scan.nodes.urls')),
    # REST API v1
    path('api/v1/', include('scanner.api.urls')),
]
