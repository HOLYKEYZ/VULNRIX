"""
URL configuration for accounts app.
"""
from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from . import github_oauth

app_name = 'accounts'

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # GitHub OAuth
    path('github/login/', github_oauth.github_login, name='github_login'),
    path('github/login/callback/', github_oauth.github_callback, name='github_callback'),
]

