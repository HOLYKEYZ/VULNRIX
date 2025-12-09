"""
Advanced Keyword Logic Filter
Pre-filters code to identify high-risk areas before LLM analysis.
"""

import re
from typing import List, Tuple

class KeywordFilter:
    """
    Scans code for suspicious keywords to determine if LLM analysis is needed.
    """
    
    def __init__(self):
        self.CATEGORIES = {
            "USER_INPUT": [
                r"request\.", r"argv", r"input\(", r"params", r"query", r"body", 
                r"headers", r"cookies", r"form", r"json", r"req\.", r"ctx\.",
                r"event\[", r"context\[", r"args\[", r"kwargs", r"getenv"
            ],
            "DATABASE": [
                r"SELECT", r"INSERT", r"UPDATE", r"DELETE", r"FROM", r"WHERE",
                r"cursor", r"execute", r"commit", r"rollback", r"sqlite3", 
                r"sqlalchemy", r"pymysql", r"psycopg2", r"mongo", r"query\(",
                r"raw\(", r"raw_sql", r"db\.", r"connection\."
            ],
            "DANGEROUS_FUNC": [
                r"eval\(", r"exec\(", r"system\(", r"popen", r"subprocess",
                r"pickle\.load", r"yaml\.load", r"unsafe", r"shell=True",
                r"compile\(", r"__import__", r"getattr\(", r"setattr\(",
                r"globals\(", r"locals\(", r"os\.system", r"commands\."
            ],
            "CRYPTO": [
                r"md5", r"sha1", r"des", r"rc4", r"crypto", r"cipher", 
                r"encrypt", r"decrypt", r"private_key", r"secret", r"password",
                r"api_key", r"token", r"credential", r"auth"
            ],
            "NETWORK": [
                r"requests\.", r"urllib", r"socket", r"http", r"fetch", 
                r"axios", r"curl", r"wget", r"ssl", r"verify=False"
            ],
            "FILESYSTEM": [
                r"open\(", r"read\(", r"write\(", r"os\.path", r"shutil", 
                r"fs\.", r"file", r"path\.join", r"readFile", r"writeFile"
            ],
            "HARDCODED_SECRETS": [
                r"password\s*=\s*['\"]", r"api_key\s*=\s*['\"]", r"secret\s*=\s*['\"]",
                r"token\s*=\s*['\"]", r"AWS_", r"PRIVATE_KEY", r"-----BEGIN"
            ],
            "INJECTION": [
                r"f\".*\{", r"f'.*\{", r"\.format\(", r"\%s", r"\+.*\+",
                r"innerHTML", r"document\.write", r"dangerouslySetInnerHTML"
            ],
            "DESERIALIZATION": [
                r"pickle\.", r"marshal\.", r"yaml\.load", r"json\.loads",
                r"unserialize", r"ObjectInputStream", r"readObject"
            ]
        }

    def scan(self, code: str) -> Tuple[bool, List[str], int]:
        """
        Returns:
        - is_suspicious (bool): True if LLM scan is required.
        - categories (List[str]): List of matched categories.
        - risk_score (int): 0-100 score based on matches.
        """
        found_categories = set()
        total_matches = 0
        
        for category, patterns in self.CATEGORIES.items():
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    found_categories.add(category)
                    total_matches += 1
                    # Optimization: Don't need to count every match, just presence
                    break
        
        # Risk Calculation
        risk_score = 0
        if "DANGEROUS_FUNC" in found_categories:
            risk_score += 40
        if "DATABASE" in found_categories and "USER_INPUT" in found_categories:
            risk_score += 40
        if "DATABASE" in found_categories:
            risk_score += 20
        if "CRYPTO" in found_categories:
            risk_score += 20
        if "FILESYSTEM" in found_categories and "USER_INPUT" in found_categories:
            risk_score += 30
        if "HARDCODED_SECRETS" in found_categories:
            risk_score += 50
        if "INJECTION" in found_categories:
            risk_score += 35
        if "DESERIALIZATION" in found_categories:
            risk_score += 40
        if "USER_INPUT" in found_categories:
            risk_score += 10
            
        risk_score = min(risk_score, 100)
        
        # Threshold for LLM - always scan if any category found
        is_suspicious = len(found_categories) > 0
        
        return is_suspicious, list(found_categories), risk_score
