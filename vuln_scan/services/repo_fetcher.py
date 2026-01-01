
"""
Service for fetching repositories and handling file uploads.
Includes Zip-Slip prevention and shallow cloning.
"""
import os
import subprocess
import zipfile
import logging
from typing import List, Tuple
from .file_filter import is_safe_file
from .scan_limiter import validate_project_limits

logger = logging.getLogger("vuln_scan")

def clone_repo(repo_url: str, target_dir: str) -> Tuple[bool, str]:
    """
    Shallow clone a git repository to target_dir.
    Returns (True, "") if successful, (False, error_message) if failed.
    """
    try:
        # Security check: Ensure URL is valid (basic check)
        if not repo_url.startswith(('http://', 'https://')):
            return False, "Invalid Protocol: URL must start with http:// or https://"
            
        # Run git clone --depth 1
        cmd = ['git', 'clone', '--depth', '1', repo_url, target_dir]
        
        # nosec: Subprocess is used with fixed arguments and validated URL
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=30 # Hard timeout for clone
        )
        
        if result.returncode != 0:
            error_msg = result.stderr.strip() or "Unknown Git Error"
            logger.error(f"Git clone failed: {error_msg}")
            return False, error_msg
            
        return True, ""
    except subprocess.TimeoutExpired:
        logger.error("Git clone timed out")
        return False, "Git Clone Timed Out (30s limit)"
    except Exception as e:
        logger.error(f"Git clone error: {e}")
        return False, f"Git Error: {str(e)}"

def extract_zip(zip_path: str, target_dir: str) -> bool:
    """
    Extract a zip file to target_dir with Zip-Slip prevention.
    """
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.infolist():
                # Block nested archives
                if member.filename.lower().endswith(('.zip', '.tar', '.gz', '.rar', '.7z')):
                    continue
                    
                # Zip-Slip Prevention
                # Resolve the canonical path
                target_path = os.path.join(target_dir, member.filename)
                abs_target_path = os.path.abspath(target_path)
                abs_destination = os.path.abspath(target_dir)
                
                # Check if the path is safely inside the destination
                if not abs_target_path.startswith(abs_destination):
                    logger.warning(f"Zip-Slip attempt detected: {member.filename}")
                    continue
                
                # Extract
                zf.extract(member, target_dir)
        return True
    except Exception as e:
        logger.error(f"Zip extract error: {e}")
        return False

def get_project_files(target_dir: str) -> List[str]:
    """
    Walk directory, filter files, and enforce limits.
    Returns list of absolute file paths to scan.
    """
    valid_files = []
    total_size_mb = 0.0
    file_count = 0
    
    for root, _, files in os.walk(target_dir):
        # Skip .git directory
        if '.git' in root:
            continue
            
        for file in files:
            file_path = os.path.join(root, file)
            
            # 1. Filter Check
            if not is_safe_file(file_path):
                continue
                
            # 2. Count & Size Check
            try:
                size_mb = os.path.getsize(file_path) / (1024 * 1024)
                total_size_mb += size_mb
                file_count += 1
                
                # 3. Limit Validation (Raises exception if busted)
                validate_project_limits(file_count, total_size_mb)
                
                valid_files.append(file_path)
                
            except OSError:
                continue
                
    return valid_files
