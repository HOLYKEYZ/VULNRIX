"""
GitHub Webhook handler for VULNRIX.
Receives GitHub events and triggers scans.
"""
import hmac
import hashlib
import json
import logging
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.shortcuts import redirect, render
from django.conf import settings
import os
import logging

logger = logging.getLogger(__name__)


def verify_webhook_signature(payload: bytes, signature: str) -> bool:
    """Verify the webhook signature using HMAC-SHA256."""
    secret = os.environ.get('GITHUB_WEBHOOK_SECRET', '').encode()
    if not secret:
        logger.warning("GITHUB_WEBHOOK_SECRET not set, skipping verification")
        return True  # Allow in dev, but log warning
    
    if not signature or not signature.startswith('sha256='):
        return False
    
    expected_sig = 'sha256=' + hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_sig, signature)


@csrf_exempt
@require_http_methods(["POST"])
def webhook_handler(request):
    """
    Handle GitHub webhook events.
    Supported events: push, pull_request, installation
    """
    # Verify signature
    signature = request.headers.get('X-Hub-Signature-256', '')
    if not verify_webhook_signature(request.body, signature):
        logger.warning("Invalid webhook signature")
        return HttpResponse("Invalid signature", status=403)
    
    event_type = request.headers.get('X-GitHub-Event', '')
    delivery_id = request.headers.get('X-GitHub-Delivery', '')
    
    logger.info(f"Received GitHub webhook: event={event_type}, delivery={delivery_id}")
    
    try:
        payload = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    
    # Route to handler based on event type
    if event_type == 'push':
        return handle_push_event(payload)
    elif event_type == 'pull_request':
        return handle_pull_request_event(payload)
    elif event_type == 'installation':
        return handle_installation_event(payload)
    elif event_type == 'ping':
        return JsonResponse({"message": "pong"})
    else:
        logger.info(f"Unhandled event type: {event_type}")
        return JsonResponse({"message": f"Event {event_type} received but not handled"})


def handle_push_event(payload: dict) -> JsonResponse:
    """
    Handle push event - trigger a scan on the pushed commits.
    """
    repo = payload.get('repository', {})
    repo_name = repo.get('full_name', 'unknown')
    ref = payload.get('ref', '')
    commits = payload.get('commits', [])
    installation_id = payload.get('installation', {}).get('id')
    
    logger.info(f"Push event: {repo_name} -> {ref}, {len(commits)} commits")
    
    if not installation_id:
        logger.warning("No installation_id in push event")
        return JsonResponse({"error": "No installation_id"}, status=400)
    
    # TODO: Queue a background scan
    # For now, just log and acknowledge
    # In production, you would:
    # 1. Clone the repo using the installation token
    # 2. Run the VULNRIX scanner
    # 3. Post results as a check run or comment
    
    # Get changed files from commits
    changed_files = set()
    for commit in commits:
        changed_files.update(commit.get('added', []))
        changed_files.update(commit.get('modified', []))
    
    logger.info(f"Changed files: {changed_files}")
    
    return JsonResponse({
        "message": "Push event received",
        "repo": repo_name,
        "ref": ref,
        "changed_files": list(changed_files)[:20],  # Limit for response
    })


def handle_pull_request_event(payload: dict) -> JsonResponse:
    """
    Handle pull_request event - scan PR changes with AI security review.
    """
    action = payload.get('action', '')
    pr = payload.get('pull_request', {})
    repo = payload.get('repository', {})
    installation_id = payload.get('installation', {}).get('id')
    
    repo_name = repo.get('full_name', 'unknown')
    owner, repo_short = repo_name.split('/') if '/' in repo_name else ('', repo_name)
    pr_number = pr.get('number', 0)
    pr_title = pr.get('title', '')
    diff_url = pr.get('diff_url', '')
    
    logger.info(f"PR event: {action} on {repo_name}#{pr_number} - {pr_title}")
    
    # Only scan on opened or synchronize (new commits pushed)
    if action not in ['opened', 'synchronize']:
        return JsonResponse({"message": f"PR action {action} ignored"})
    
    if not installation_id:
        logger.warning("No installation_id in PR event")
        return JsonResponse({"error": "No installation_id"}, status=400)
    
    # Fetch the PR diff
    try:
        import requests
        diff_response = requests.get(diff_url, timeout=30)
        if diff_response.status_code != 200:
            logger.error(f"Failed to fetch diff: {diff_response.status_code}")
            return JsonResponse({"message": "PR received but diff fetch failed"})
        
        diff_content = diff_response.text
        
        # Get changed file paths from diff
        file_paths = []
        for line in diff_content.split('\n'):
            if line.startswith('+++ b/'):
                file_paths.append(line[6:])
        
        # Run AI security review
        from .auto_fix import review_pr_for_security, post_pr_review_comment
        from .services import github_app
        
        review_result = review_pr_for_security(diff_content, file_paths)
        
        # Post review as comment
        post_pr_review_comment(github_app, installation_id, owner, repo_short, pr_number, review_result)
        
        logger.info(f"AI review completed for {repo_name}#{pr_number}: secure={review_result.get('is_secure')}")
        
        return JsonResponse({
            "message": "PR reviewed",
            "action": action,
            "repo": repo_name,
            "pr_number": pr_number,
            "is_secure": review_result.get('is_secure', True),
            "issues_found": len(review_result.get('issues', []))
        })
        
    except Exception as e:
        logger.error(f"PR review failed: {e}")
        return JsonResponse({
            "message": "PR event received, review failed",
            "action": action,
            "repo": repo_name,
            "pr_number": pr_number,
            "error": str(e)
        })


def handle_installation_event(payload: dict) -> JsonResponse:
    """
    Handle installation event - store/remove installation in database.
    """
    from vuln_scan.web_dashboard.models import GitHubInstallation
    from django.contrib.auth.models import User
    
    action = payload.get('action', '')
    installation = payload.get('installation', {})
    installation_id = installation.get('id')
    account = installation.get('account', {})
    account_login = account.get('login', 'unknown')
    account_type = account.get('type', 'User')
    sender = payload.get('sender', {})
    sender_login = sender.get('login', '')
    
    logger.info(f"Installation event: {action} by {account_login} (id={installation_id})")
    
    if action == 'created':
        # Find user by GitHub username (from OAuth or sender)
        # 1. Try standard 'gh_' username
        user = User.objects.filter(username=f"gh_{sender_login}").first()
        if not user:
            user = User.objects.filter(username=f"gh_{account_login}").first()
            
        # 2. Try linked profile (Normal Email User)
        if not user:
            from accounts.models import UserProfile
            try:
                # Check sender login
                profile = UserProfile.objects.filter(github_username__iexact=sender_login).first()
                if not profile:
                    # Check account login (if it's a user install)
                    profile = UserProfile.objects.filter(github_username__iexact=account_login).first()
                
                if profile:
                    user = profile.user
            except Exception as e:
                logger.warning(f"Failed to lookup profile: {e}")
        
        if user:
            GitHubInstallation.objects.update_or_create(
                installation_id=installation_id,
                defaults={
                    'user': user,
                    'account_login': account_login,
                    'account_type': account_type,
                }
            )
            logger.info(f"Saved installation for user {user.username}")
        else:
            # Create orphan installation (will be claimed later)
            logger.warning(f"No user found for {sender_login} or {account_login}, installation not linked")
    
    elif action == 'deleted':
        GitHubInstallation.objects.filter(installation_id=installation_id).delete()
        logger.info(f"Deleted installation {installation_id}")
    
    return JsonResponse({
        "message": f"Installation {action}",
        "account": account_login,
        "installation_id": installation_id,
    })


# ============================================================================
# API Views for Dashboard
# ============================================================================
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_GET
import requests as http_requests


@login_required
@require_GET
def get_connected_repos(request):
    """Get list of repos the user has connected via GitHub App."""
    from vuln_scan.web_dashboard.models import GitHubInstallation
    from .services import github_app
    
    installations = GitHubInstallation.objects.filter(user=request.user)
    
    if not installations.exists():
        return JsonResponse({"connected": False, "repos": []})
    
    all_repos = []
    for install in installations:
        try:
            token = github_app.get_installation_token(install.installation_id)
            
            # Fetch repos accessible to this installation
            response = http_requests.get(
                "https://api.github.com/installation/repositories",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
                timeout=10
            )
            
            if response.status_code == 200:
                repos = response.json().get('repositories', [])
                for repo in repos:
                    all_repos.append({
                        'id': repo.get('id'),
                        'name': repo.get('name'),
                        'full_name': repo.get('full_name'),
                        'owner': repo.get('owner', {}).get('login'),
                        'private': repo.get('private'),
                        'installation_id': install.installation_id,
                    })
        except Exception as e:
            logger.error(f"Failed to fetch repos for installation {install.installation_id}: {e}")
    
    return JsonResponse({
        "connected": True,
        "repos": all_repos,
        "installations": [
            {"id": i.installation_id, "account": i.account_login}
            for i in installations
        ]
    })


@login_required
@require_http_methods(["POST"])
def trigger_repo_scan(request):
    """Trigger a scan on a connected GitHub repo."""
    import json as json_lib
    from .services import github_app
    from vuln_scan.web_dashboard.models import GitHubInstallation
    
    try:
        data = json_lib.loads(request.body)
    except:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    
    installation_id = data.get('installation_id')
    repo_full_name = data.get('repo_full_name')  # owner/repo
    
    if not installation_id or not repo_full_name:
        return JsonResponse({"error": "Missing installation_id or repo_full_name"}, status=400)
    
    # Verify ownership
    install = GitHubInstallation.objects.filter(
        installation_id=installation_id, 
        user=request.user
    ).first()
    
    if not install:
        return JsonResponse({"error": "Installation not found or not owned"}, status=403)
    
    # Authenticate and get token
    try:
        token = github_app.get_installation_token(install.installation_id)
    except Exception as e:
        logger.error(f"Failed to get installation token: {e}")
        return JsonResponse({"error": "Failed to authenticate with GitHub"}, status=500)

    # Check Quota
    from vuln_scan.services.scan_limiter import check_and_increment_usage, DailyQuotaExceeded
    try:
        check_and_increment_usage(request.user)
    except DailyQuotaExceeded as e:
        return JsonResponse({"error": str(e)}, status=403)

    # Prepare Scan Project
    from vuln_scan.web_dashboard.models import ScanProject, ScanFileResult
    from vuln_scan.services.repo_fetcher import clone_repo
    from vuln_scan.services.file_filter import is_safe_file
    import shutil
    import tempfile
    from pathlib import Path

    SCAN_TEMP_BASE = Path(tempfile.gettempdir()) / "vulnrix_scans"
    SCAN_TEMP_BASE.mkdir(exist_ok=True)

    owner, repo_name = repo_full_name.split('/')
    project_name = repo_name
    
    # Create Project Record
    project = ScanProject.objects.create(
        user=request.user,
        name=project_name,
        repo_url=f"https://github.com/{repo_full_name}", # Display URL
        status='INITIALIZING'
    )
    
    # Directory setup
    project_dir = SCAN_TEMP_BASE / str(project.id)
    if project_dir.exists():
        shutil.rmtree(project_dir)
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Construct Authenticated URL for Cloning
    auth_repo_url = f"https://x-access-token:{token}@github.com/{repo_full_name}.git"

    # Clone
    success, error_msg = clone_repo(auth_repo_url, str(project_dir))
    if not success:
        project.status = 'ERROR'
        project.save()
        return JsonResponse({"error": f"Clone Failed: {error_msg}"}, status=400)
    
    # Discover files
    files_created = []
    current_limit = 500  # Sync with web_dashboard views
    
    for root, _, files in os.walk(project_dir):
        if '.git' in root: continue
        
        for file in files:
            full_path = Path(root) / file
            rel_path = full_path.relative_to(project_dir)
            
            if is_safe_file(str(full_path)):
                res = ScanFileResult.objects.create(
                    project=project,
                    filename=str(rel_path).replace('\\', '/'),
                    status='PENDING'
                )
                files_created.append(res)
                
                if len(files_created) >= current_limit:
                    break
        if len(files_created) >= current_limit:
            break
            
    project.total_files = len(files_created)
    project.status = 'READY'
    project.save()
    
    return JsonResponse({
        "message": "Scan queued successfully",
        "project_id": project.id,
        "repo": repo_full_name,
        "total_files": project.total_files
    })


@login_required
@require_http_methods(["POST"])
def trigger_auto_fix(request):
    """Trigger auto-fix PR for a repo."""
    import json as json_lib
    from .services import github_app
    from .auto_fix import create_dependency_fix_pr
    from vuln_scan.web_dashboard.models import GitHubInstallation
    
    try:
        data = json_lib.loads(request.body)
    except:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    
    installation_id = data.get('installation_id')
    repo_full_name = data.get('repo_full_name')
    findings = data.get('findings', [])  # SCA findings with package info
    
    if not installation_id or not repo_full_name:
        return JsonResponse({"error": "Missing installation_id or repo_full_name"}, status=400)
    
    # Verify ownership
    install = GitHubInstallation.objects.filter(
        installation_id=installation_id, 
        user=request.user
    ).first()
    
    if not install:
        return JsonResponse({"error": "Installation not found or not owned"}, status=403)
    
    owner, repo = repo_full_name.split('/')
    
    try:
        pr = create_dependency_fix_pr(github_app, installation_id, owner, repo, findings)
        if pr:
            return JsonResponse({
                "message": "Fix PR created",
                "pr_url": pr.get('html_url'),
                "pr_number": pr.get('number'),
            })
        else:
            return JsonResponse({"message": "No fixes needed or PR creation failed"})
    except Exception as e:
        logger.error(f"Auto-fix failed: {e}")
@login_required
def github_dashboard(request):
    """
    Dedicated dashboard for GitHub integration.
    Shows connected repos and actions.
    """
    from vuln_scan.web_dashboard.models import GitHubInstallation
    from .services import github_app
    import requests as http_requests

    user_installations = GitHubInstallation.objects.filter(user=request.user)
    
    # Check if connected
    connected = user_installations.exists()
    repos_list = []
    
    if connected:
        for install in user_installations:
            try:
                token = github_app.get_installation_token(install.installation_id)
                response = http_requests.get(
                    "https://api.github.com/installation/repositories",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/vnd.github+json",
                    },
                    timeout=5
                )
                if response.status_code == 200:
                    data = response.json()
                    for r in data.get('repositories', []):
                        r['installation_id'] = install.installation_id
                        repos_list.append(r)
            except Exception as e:
                logger.error(f"Error fetching repos for {install}: {e}")

    return render(request, 'github_app/dashboard.html', {
        'connected': connected,
        'repos': repos_list,
    })

