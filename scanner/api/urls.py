"""
API URL routing for VULNRIX REST API v1.
"""

from django.urls import path
from . import views

app_name = 'api'

urlpatterns = [
    # Health check
    path('health', views.health, name='health'),
    
    # API documentation
    path('docs', views.api_docs, name='docs'),
    
    # OSINT endpoints
    path('osint/scan', views.osint_scan, name='osint_scan'),
    
    # Code scanning endpoints
    path('code/scan', views.code_scan, name='code_scan'),
    
    # Breach checking endpoints
    path('breach/check', views.breach_check, name='breach_check'),
]
