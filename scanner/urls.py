"""
URL configuration for scanner app.
"""
from django.urls import path
from . import views
from . import views_fallback

app_name = 'scanner'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('api/stats/', views.dashboard_stats_api, name='dashboard_stats_api'),
    path('new/', views.new_scan, name='new_scan'),
    path('docs/', views.docs, name='docs'),
    path('<int:scan_id>/', views.view_scan, name='view_scan'),
    
    # Fallback monitoring
    path('fallback/', views_fallback.fallback_dashboard, name='fallback_dashboard'),
    path('api/fallback/stats/', views_fallback.fallback_stats_api, name='fallback_stats_api'),
    path('api/fallback/health/', views_fallback.api_health_api, name='api_health_api'),
    path('api/fallback/clear/', views_fallback.clear_metrics, name='clear_metrics'),
]

