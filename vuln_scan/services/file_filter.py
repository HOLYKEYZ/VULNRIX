
"""
Service for filtering files during repository or zip scanning.
Enforces security rules and resource limits.
"""
import os

# Hard limits for Render Free Tier
MAX_FILE_SIZE = 200 * 1024  # 200KB
BINARY_EXTENSIONS = {
    '.exe', '.dll', '.so', '.dylib', '.bin', '.iso', '.img', '.dmg',
    '.zip', '.tar', '.gz', '.7z', '.rar',
    '.jpg', '.png', '.gif', '.bmp', '.ico', '.svg', '.webp',
    '.mp3', '.mp4', '.wav', '.avi', '.mov',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.pyc', '.pyo', '.pyd', '.class', '.o', '.obj'
}

# Allowed source code extensions (Allow-list approach is safer)
SOURCE_EXTENSIONS = {
    '.py', '.js', '.jsx', '.ts', '.tsx', '.html', '.css', '.c', '.cpp', '.h', '.hpp',
    '.java', '.go', '.rs', '.php', '.rb', '.sh', '.bash', '.yaml', '.yml', '.json',
    '.xml', '.sql', '.dockerfile', 'dockerfile', '.lock'
}

def is_safe_file(file_path: str) -> bool:
    """
    Check if a file is safe to scan.
    
    Checks:
    1. Extension allow-list
    2. File Size (< 200KB)
    3. Binary content check (null bytes)
    """
    if not os.path.exists(file_path):
        return False
        
    # 1. Check Extension
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()
    
    # Special handling for Dockerfile which might have no extension
    filename = os.path.basename(file_path).lower()
    if filename == 'dockerfile':
        ext = '.dockerfile'

    if ext in BINARY_EXTENSIONS:
        return False
        
    if ext not in SOURCE_EXTENSIONS:
        # Strict mode: Only allow known source extensions
        return False
        
    # 2. Check File Size
    try:
        size = os.path.getsize(file_path)
        if size > MAX_FILE_SIZE:
            return False
        if size == 0:
            return False
            
    except OSError:
        return False
        
    # 3. Check for Binary Content (Null Bytes)
    # Read first 1024 bytes to check
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            if b'\0' in chunk:
                return False
    except Exception:
        return False
        
    return True
