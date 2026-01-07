
"""
Service for enforcing scan limits and quotas.
Ensures users don't exceed daily allowances or resource caps.
"""
from django.utils import timezone
from ..web_dashboard.models import ScanUsage, ScanProject

# Configuration Limits
MAX_SCANS_PER_DAY = 20
MAX_FILES_PER_REPO_SCAN = 50
MAX_PROJECT_SIZE_MB = 5

class ScanLimitExceeded(Exception):
    """Exception raised when a scan limit is exceeded."""
    pass

class DailyQuotaExceeded(ScanLimitExceeded):
    """Exception raised when daily scan quota is reached."""
    pass

def check_and_increment_usage(user) -> bool:
    """
    Check if user has quota remaining for today.
    If yes, increment usage and return True.
    If no, raise DailyQuotaExceeded.
    """
    if user.is_superuser:
        return True
        
    usage, created = ScanUsage.objects.get_or_create(user=user)
    
    # Reset if it's a new day
    usage.reset_if_new_day()
    
    if usage.scans_today >= MAX_SCANS_PER_DAY:
        raise DailyQuotaExceeded(f"Daily limit of {MAX_SCANS_PER_DAY} scans reached. Please try again tomorrow.")
        
    # Increment usage (optimistic, caller should roll back if scan fails immediately)
    usage.scans_today += 1
    usage.save()
    return True

def validate_project_limits(file_count: int, total_size_mb: float, bypass: bool = False):
    """
    Validate that a project (repo/zip) is within limits.
    """
    if bypass:
        return # Skip checks if bypass is enabled (e.g. Snyk fallback)

    if file_count > MAX_FILES_PER_REPO_SCAN:
        raise ScanLimitExceeded(f"Project has {file_count} files. Max allowed is {MAX_FILES_PER_REPO_SCAN}.")
        
    if total_size_mb > MAX_PROJECT_SIZE_MB:
        raise ScanLimitExceeded(f"Project size {total_size_mb:.2f}MB exceeds limit of {MAX_PROJECT_SIZE_MB}MB.")
