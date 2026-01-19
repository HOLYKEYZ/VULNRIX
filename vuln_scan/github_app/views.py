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
from django.conf import settings
import os

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
    Handle installation event - track when the app is installed/uninstalled.
    """
    action = payload.get('action', '')
    installation = payload.get('installation', {})
    installation_id = installation.get('id')
    account = installation.get('account', {})
    account_login = account.get('login', 'unknown')
    
    logger.info(f"Installation event: {action} by {account_login} (id={installation_id})")
    
    # TODO: Store installation in database for later use
    # This would allow users to see which repos they've connected
    
    return JsonResponse({
        "message": f"Installation {action}",
        "account": account_login,
        "installation_id": installation_id,
    })
