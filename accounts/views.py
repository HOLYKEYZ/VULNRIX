"""
Django views for accounts app - minimal auth.
"""
from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from .forms import CustomUserCreationForm, CustomAuthenticationForm


@require_http_methods(["GET", "POST"])
def register(request):
    """User registration."""
    if request.user.is_authenticated:
        return redirect('vuln_scan:dashboard')
    
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')

            # Authenticate the user so Django knows which backend was used
            authenticated_user = authenticate(request, username=username, password=raw_password)
            if authenticated_user is not None:
                login(request, authenticated_user)
                messages.success(request, f'Welcome to VULNRIX, {username}!')
                # Always redirect to Code Scanner Dashboard
                return redirect('vuln_scan:dashboard')
            else:
                messages.error(request, 'Account created, but automatic login failed. Please log in manually.')
    else:
        form = CustomUserCreationForm()
    return render(request, 'register.html', {'form': form})


@require_http_methods(["GET", "POST"])
def login_view(request):
    """User login."""
    if request.user.is_authenticated:
        return redirect('vuln_scan:dashboard')
    
    if request.method == 'POST':
        form = CustomAuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome back, {user.username}!')
                
                # Always redirect to Code Scanner Dashboard
                return redirect('vuln_scan:dashboard')
            else:
                messages.error(request, 'Invalid username/email or password.')
    else:
        form = CustomAuthenticationForm()
    return render(request, 'login.html', {'form': form})


def logout_view(request):
    """User logout."""
    from django.contrib.auth import logout
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('accounts:login')
