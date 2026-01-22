"""
GitHub OAuth for VULNRIX.
Handles "Login with GitHub" flow using GitHub App OAuth.
"""
import os
import requests
import logging
from django.shortcuts import redirect
from django.http import JsonResponse
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.conf import settings

logger = logging.getLogger(__name__)

# GitHub OAuth URLs
GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_API = "https://api.github.com/user"
GITHUB_EMAILS_API = "https://api.github.com/user/emails"


def github_login(request):
    """Redirect user to GitHub OAuth authorization page."""
    client_id = os.environ.get('GITHUB_CLIENT_ID')
    if not client_id:
        return JsonResponse({"error": "GitHub App not configured"}, status=500)
    
    # Build callback URL
    callback_url = request.build_absolute_uri('/accounts/github/login/callback/')
    
    # Scopes: read:user for profile, user:email for email
    scope = "read:user user:email"
    
    auth_url = (
        f"{GITHUB_AUTHORIZE_URL}"
        f"?client_id={client_id}"
        f"&redirect_uri={callback_url}"
        f"&scope={scope}"
    )
    
    return redirect(auth_url)


def github_callback(request):
    """Handle GitHub OAuth callback, exchange code for token, login/create user."""
    code = request.GET.get('code')
    error = request.GET.get('error')
    
    if error:
        logger.error(f"GitHub OAuth error: {error}")
        return redirect('/accounts/login/?error=github_denied')
    
    if not code:
        return redirect('/accounts/login/?error=no_code')
    
    client_id = os.environ.get('GITHUB_CLIENT_ID')
    client_secret = os.environ.get('GITHUB_CLIENT_SECRET')
    
    if not client_id or not client_secret:
        return JsonResponse({"error": "GitHub App not configured"}, status=500)
    
    # Exchange code for access token
    token_response = requests.post(
        GITHUB_TOKEN_URL,
        headers={"Accept": "application/json"},
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
        },
        timeout=10
    )
    
    if token_response.status_code != 200:
        logger.error(f"GitHub token exchange failed: {token_response.text}")
        return redirect('/accounts/login/?error=token_failed')
    
    token_data = token_response.json()
    access_token = token_data.get('access_token')
    
    if not access_token:
        logger.error(f"No access token in response: {token_data}")
        return redirect('/accounts/login/?error=no_token')
    
    # Fetch user profile
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    
    user_response = requests.get(GITHUB_USER_API, headers=headers, timeout=10)
    if user_response.status_code != 200:
        logger.error(f"GitHub user fetch failed: {user_response.text}")
        return redirect('/accounts/login/?error=user_failed')
    
    github_user = user_response.json()
    github_id = github_user.get('id')
    github_username = github_user.get('login')
    github_name = github_user.get('name') or github_username
    
    # Fetch email (might be private)
    email = github_user.get('email')
    if not email:
        emails_response = requests.get(GITHUB_EMAILS_API, headers=headers, timeout=10)
        if emails_response.status_code == 200:
            emails = emails_response.json()
            primary = next((e for e in emails if e.get('primary')), None)
            if primary:
                email = primary.get('email')
    
    if not email:
        email = f"{github_username}@github.vulnrix.local"  # Fallback
    
    # Find or create user
    # Strategy: Match by email first, then by github username
    user = None
    
    # 1. LINKING MODE: If user is already logged in, link this GitHub account to them
    if request.user.is_authenticated:
        user = request.user
        logger.info(f"Linking GitHub account {github_username} to existing user {user.username}")
        # Store GitHub username in user profile if needed (or just rely on installation link)
        # For now, we rely on the implementation sync block below
    else:
        # 2. LOGIN MODE: Find existing user or create new one
        user = User.objects.filter(email=email).first()
        
        if not user:
            # Try matching by username (prefixed with gh_)
            user = User.objects.filter(username=f"gh_{github_username}").first()
        
        if not user:
            # Create new user
            user = User.objects.create_user(
                username=f"gh_{github_username}",
                email=email,
                first_name=github_name,
            )
            user.set_unusable_password()  # No password (OAuth only)
            user.save()
            logger.info(f"Created new user from GitHub: {user.username}")
        
        # Login the user
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')
    
    # =========================================================================
    # SYNC INSTALLATIONS
    # Fetch user's installations using the OAuth token to ensure DB is in sync
    # =========================================================================
    try:
        from vuln_scan.web_dashboard.models import GitHubInstallation
        
        installations_response = requests.get(
            "https://api.github.com/user/installations",
            headers=headers,  # Includes OAuth token
            timeout=10
        )
        
        if installations_response.status_code == 200:
            installations_data = installations_response.json()
            # The structure is usually {"total_count": N, "installations": [...]}
            install_list = installations_data.get('installations', [])
            
            current_ids = []
            for install in install_list:
                inst_id = install.get('id')
                account_login = install.get('account', {}).get('login')
                account_type = install.get('account', {}).get('type', 'User')
                
                # Check if this app installation belongs to our app 
                # (via app_id matching if needed, but endpoint returns ONLY our app installs)
                
                GitHubInstallation.objects.update_or_create(
                    installation_id=inst_id,
                    defaults={
                        'user': user,
                        'account_login': account_login,
                        'account_type': account_type
                    }
                )
                current_ids.append(inst_id)
                logger.info(f"Synced installation {inst_id} for {user.username}")
                
            # Optional: Remove stale installations?
            # GitHubInstallation.objects.filter(user=user).exclude(installation_id__in=current_ids).delete()
            
        else:
            logger.warning(f"Failed to sync installations: {installations_response.status_code}")
            
    except Exception as e:
        logger.error(f"Error syncing installations: {e}")
    
    # Redirect to new GitHub dashboard
    next_url = request.GET.get('next', '/github/dashboard/')
    return redirect(next_url)
