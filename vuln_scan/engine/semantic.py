"""
CodeQL-Style Semantic Analysis Engine
Supports: Python, JavaScript, Java, Go, PHP, Ruby, C/C++, C#, Rust, Swift, Kotlin, TypeScript, SQL, Shell
"""
import re
from typing import Dict, Any, List, Optional

class SemanticAnalyzer:
    def __init__(self):
        self._init_sources()
        self._init_sinks()
        self._init_secrets()
        self._init_bugs()
        self._init_sanitizers()
        self._init_lang_dangerous()
    
    def _init_sources(self):
        self.SOURCES = {
            "python": [r"request\.args", r"request\.form", r"request\.json", r"sys\.argv", r"os\.environ", r"input\("],
            "javascript": [r"req\.body", r"req\.query", r"req\.params", r"process\.argv", r"process\.env", r"document\.getElementById"],
            "java": [r"request\.getParameter", r"request\.getAttribute", r"Scanner\(System\.in\)", r"args\["],
            "go": [r"r\.FormValue", r"r\.URL\.Query", r"os\.Args", r"os\.Getenv"],
            "php": [r"\$_GET", r"\$_POST", r"\$_REQUEST", r"\$_COOKIE", r"\$_SERVER"],
            "ruby": [r"params\[", r"request\.", r"ARGV", r"ENV\["],
            "c": [r"argv\[", r"scanf\(", r"gets\(", r"fgets\(", r"getenv\("],
            "rust": [r"std::env::args", r"std::env::var", r"std::io::stdin"],
            "csharp": [r"Request\[", r"Request\.Form", r"Request\.QueryString"],
            "swift": [r"CommandLine\.arguments"],
            "kotlin": [r"request\.getParameter", r"args\["],
        }
    
    def _init_sinks(self):
        self.SINKS = {
            "python": {
                "SQL Injection": [r"execute\s*\(", r"executemany\s*\(", r"cursor\.execute"],
                "Command Injection": [r"os\.system", r"subprocess\.", r"popen", r"eval\(", r"exec\("],
                "Path Traversal": [r"open\(", r"os\.path\.join"],
                "Deserialization": [r"pickle\.load", r"yaml\.load", r"marshal\.load"],
                "SSRF": [r"requests\.get", r"requests\.post", r"urllib\.request"]
            },
            "javascript": {
                "SQL Injection": [r"query\(", r"execute\("],
                "Command Injection": [r"exec\(", r"spawn\(", r"execSync"],
                "XSS": [r"\.innerHTML\s*=", r"document\.write\(", r"\.html\("],
            }
        }
    def _init_secrets(self):
        self.SECRETS = [
            # Cloud & Infrastructure
            r"(?i)aws_access_key_id\s*=\s*['\"][A-Z0-9]{20}['\"]",
            r"(?i)aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]",
            r"AKIA[0-9A-Z]{16}",  # AWS Access Key ID
            r"(?i)google_api_key\s*=\s*['\"]AIza[0-9A-Za-z-_]{35}['\"]",  # Google API Key
            r"(?i)azure_storage_account\s*=\s*['\"][a-z0-9]{3,24}['\"]",
            r"(?i)azure_storage_access_key\s*=\s*['\"][a-zA-Z0-9/+=]{88}['\"]",
            
            # SaaS & API Keys
            r"(?i)stripe_secret_key\s*=\s*['\"]sk_live_[0-9a-zA-Z]{24}['\"]",
            r"(?i)stripe_publishable_key\s*=\s*['\"]pk_live_[0-9a-zA-Z]{24}['\"]",
            r"(?i)slack_api_token\s*=\s*['\"]xox[baprs]-[a-zA-Z0-9-]{10,}['\"]",
            r"(?i)facebook_access_token\s*=\s*['\"][a-zA-Z0-9]+['\"]",
            r"(?i)twitter_consumer_key\s*=\s*['\"][a-zA-Z0-9]{15,25}['\"]",
            r"(?i)github_token\s*=\s*['\"]ghp_[a-zA-Z0-9]{36}['\"]",
            
            # Application Secrets
            r"(?i)(password|passwd|pwd|secret|token|api_key|apikey|access_token)\s*[:=]\s*['\"][a-zA-Z0-9@#$%^&+=]{8,}['\"]",
            r"(?i)bearer\s+['\"][a-zA-Z0-9-._~+/]+=*['\"]",
            r"-----BEGIN\s+([A-Z]+\s+)?PRIVATE\s+KEY-----",
            r"-----BEGIN\s+CERTIFICATE-----",
        ]
    
    def _init_bugs(self):
        self.BUGS = {
            # Memory & Pointer Bugs
            "Null Pointer Dereference": [r"\*\s*NULL", r"None\.", r"null\.", r"\*ptr\s*=.*NULL"],
            "Uninitialized Variable": [r"char\s+\w+\[[^\]]+\];[^=]*printf", r"int\s+\w+;[^=]*\w+\s*[+\-*/]"],
            "Use After Free": [r"free\s*\([^)]+\);[^}]*\*", r"free\s*\([^)]+\);[^}]*printf"],
            "Double Free": [r"free\s*\([^)]+\);[^}]*free\s*\("],
            # Memory Leak: specific for C/C++ manuals.
            "Memory Leak": [r"malloc\s*\([^)]+\)(?!.*free)"],
            
            # Arithmetic Bugs
            "Division by Zero": [r"/\s*0[^.]", r"%\s*0[^.]"],
            "Integer Overflow": [r"unsigned.*\+.*unsigned", r"INT_MAX\s*\+", r"UINT_MAX\s*\+"],
            "Off-by-One Error": [r"for\s*\([^;]+;\s*\w+\s*<=\s*\w+\s*;", r"i\s*<=\s*sizeof", r"i\s*<=\s*strlen"],
            
            # Control Flow Bugs
            "Infinite Loop": [r"while\s*\(\s*1\s*\)", r"while\s*\(\s*true\s*\)", r"for\s*\(\s*;\s*;\s*\)"],
            "Infinite Recursion": [r"(\w+)\s*\([^)]*\)\s*\{[^}]*\1\s*\([^)]*\)\s*;[^}]*\}"],
            "Unreachable Code": [r"return[^;]*;[^}]*\w+\s*="],
            
            # Resource Bugs
            "Resource Leak": [r"fopen\s*\([^)]+\)(?!.*fclose)", r"open\s*\([^)]+\)(?!.*close)"],
            "Unchecked Return Value": [r"fopen\s*\([^)]+\);[^}]*fread", r"malloc\s*\([^)]+\);[^}]*strcpy"],
            "File Descriptor Leak": [r"socket\s*\([^)]+\)(?!.*close)", r"open\s*\([^)]+\)(?!.*close)"],

            # Concurrency Bugs & Race Conditions
            "Race Condition": [r"pthread_create", r"std::thread", r"fork\s*\(\)", r"CreateThread"],
            "Deadlock Risk": [r"pthread_mutex_lock[^}]*pthread_mutex_lock", r"lock\s*\([^)]+\)[^}]*lock\s*\("],
            "TOCTOU Race Condition": [
                r"os\.path\.exists\s*\([^)]+\).*open\s*\(",  # Python check-then-use
                r"access\s*\([^)]+\)[^{]*open\s*\(",  # C access before open
                r"File\.exists\s*\([^)]+\)[^{]*new\s+File",  # Java/C# check-then-open
                r"fs\.existsSync\s*\([^)]+\).*fs\.readFile",  # Node.js
                r"if\s+os\.path\.(isfile|isdir).*os\.(remove|unlink|rmdir)",  # Python delete race
            ],
            
            # Type Bugs
            "Type Confusion": [r"\*\s*\(\s*\w+\s*\*\s*\)\s*\w+", r"reinterpret_cast", r"\(\s*double\s*\*\s*\)\s*malloc"],
            "Signed/Unsigned Mismatch": [r"unsigned.*=.*-\d+", r"size_t.*=.*-"],
            
            # Input Validation Bugs
            "Missing Input Validation": [r"scanf\s*\([^)]+\);[^}]*\w+\[", r"gets\s*\("],
            # "Array Index Out of Bounds": [r"\[\s*\w+\s*\](?!.*if.*<.*sizeof)"],  # Too noisy for Python/JS
            
            # Insecure Deserialization
            "Insecure Deserialization (pickle)": [
                r"pickle\.loads?\s*\([^)]+\)",
                r"cPickle\.loads?\s*\(",
                r"yaml\.load\s*\([^,)]+\)(?!.*Loader)",  # YAML without safe loader
                r"yaml\.unsafe_load\s*\(",
            ],
            "Insecure Deserialization (Java)": [
                r"ObjectInputStream\s*\([^)]+\)",
                r"\.readObject\s*\(\s*\)",
                r"XMLDecoder\s*\(",
                r"XStream\s*\(\s*\)",
            ],
            "Insecure Deserialization (PHP)": [
                r"unserialize\s*\(\$_",  # Unserialize user input
                r"unserialize\s*\(\$.*\$_(GET|POST|REQUEST|COOKIE)",
            ],
            "Insecure Deserialization (Node)": [
                r"node-serialize",
                r"serialize-to-js",
                r"funcster",
            ],
            
            # Session Security Issues
            "Weak Session Token": [
                r"session_id\s*=.*random\.random",  # Python weak random
                r"session\s*=.*Math\.random",  # JS weak random
                r"session.*=.*rand\s*\(\)",  # C weak random
                r"UUID\.randomUUID\(\)\.toString\(\)\.substring",  # Truncated UUID
            ],
            "Session Fixation": [
                r"session\[['\"]id['\"]\]\s*=\s*\$_",  # PHP session ID from input
                r"request\.session\.session_key\s*=",  # Django session fixation
                r"req\.session\.id\s*=",  # Express session fixation
            ],
            "Missing Session Regeneration": [
                r"login.*{[^}]*(?!session.regenerate|regenerate_id)",  # No regeneration on login
            ],
            
            # CSRF Issues
            "Missing CSRF Protection": [
                r"@app\.route\s*\([^)]+,\s*methods\s*=\s*\[[^\]]*'POST'[^\]]*\]\)(?!.*csrf)",
                r"form.*method=['\"]post['\"](?!.*csrf)",
                r"axios\.post\s*\([^)]+\)(?!.*csrf)",
            ],
            
            # Authentication Issues  
            "Hardcoded Credentials": [
                r"password\s*=\s*['\"][^'\"]+['\"]",
                r"secret\s*=\s*['\"][^'\"]{8,}['\"]",
                r"api_key\s*=\s*['\"][^'\"]+['\"]",
                r"token\s*=\s*['\"][A-Za-z0-9+/=]{20,}['\"]",
            ],
            "Weak Password Hashing": [
                r"md5\s*\(",
                r"sha1\s*\(",
                r"hashlib\.md5",
                r"hashlib\.sha1",
                r"MessageDigest\.getInstance\s*\(['\"]MD5['\"]",
                r"MessageDigest\.getInstance\s*\(['\"]SHA-1['\"]",
            ],
            
            # Business Logic Issues
            "Mass Assignment": [
                r"\.update\s*\(\s*request\.(POST|GET|data)",  # Django/Python
                r"Object\.assign\s*\([^,]+,\s*req\.body",  # Node.js
                r"model\.fill\s*\(\$request->all\(\)",  # Laravel
            ],
            "Timing Attack Risk": [
                r"if\s+password\s*==\s*",  # Direct string comparison
                r"if\s+token\s*===?\s*",
                r"if\s+secret\s*==\s*",
            ],
            
            # Deprecated/Unsafe Functions
            "Deprecated Function (gets)": [r"\bgets\s*\("],
            "Deprecated Function (tmpnam)": [r"\btmpnam\s*\("],
            "Unsafe Function (strcpy)": [r"\bstrcpy\s*\("],
            "Unsafe Function (sprintf)": [r"\bsprintf\s*\("],
        }
        
    def _is_relevant_bug(self, bug_type: str, lang: str) -> bool:
        """Check if a bug type is relevant for the given language"""
        c_cpp_only = [
            "Null Pointer Dereference", "Use After Free", "Double Free", 
            "Memory Leak", "Type Confusion", "Buffer Overflow",
            "Signed/Unsigned Mismatch"
        ]
        
        if lang not in ["c", "cpp"] and any(b in bug_type for b in c_cpp_only):
            return False
            
        return True
    
    def _init_sanitizers(self):
        self.SANITIZERS = {
            "python": [r"escape", r"quote_plus", r"int\("],
            "javascript": [r"escape", r"encodeURIComponent", r"parseInt"]
        }
    
    def _init_lang_dangerous(self):
        self.LANG_DANGEROUS = {
            "javascript": {
                "Dangerous eval()": r"\beval\s*\(",
                "Dangerous document.write()": r"document\.write\s*\(",
                "Dangerous innerHTML": r"\.innerHTML\s*=",
                "React dangerouslySetInnerHTML": r"dangerouslySetInnerHTML\s*=|dangerouslySetInnerHTML\s*:",
                "Vue v-html": r"v-html",
                "Angular SafeHtml": r"bypassSecurityTrust",
                "JWT Decode (Unverified)": r"jwt\.decode\s*\(",
                "Dangerous setTimeout": r"setTimeout\s*\(\s*['\"]",
                "Dangerous setInterval": r"setInterval\s*\(\s*['\"]",
                "Function Constructor": r"new\s+Function\s*\(",
                "Open Redirect": r"window\.location\s*(\.href)?\s*=",
                "Insecure Cookie": r"document\.cookie\s*=",
                "Insecure LocalStorage": r"localStorage\.setItem\s*\(",
                "Prototype Pollution": r"__proto__|constructor\.prototype",
                "Insecure HTTP Fetch": r"fetch\s*\(\s*['\"]http:",
                "NoSQL Injection": r"\$where\s*:\s*|db\.[a-z]+\.find\s*\(\s*\{",
                "API Key Exposure": r"['\"](AIza|sk_live)[a-zA-Z0-9-_]+['\"]",
            },
            "typescript": {
                "Dangerous eval()": r"\beval\s*\(",
                "Dangerous innerHTML": r"\.innerHTML\s*=",
                "React dangerouslySetInnerHTML": r"dangerouslySetInnerHTML\s*=|dangerouslySetInnerHTML\s*:",
                "Type Assertion Bypass": r"as\s+any|<any>",
                "Prototype Pollution": r"__proto__|constructor\.prototype",
                "Open Redirect": r"window\.location\s*(\.href)?\s*=",
            },
            "python": {
                "Dangerous eval()": r"\beval\s*\(",
                "Dangerous exec()": r"\bexec\s*\(",
                "OS Command Injection": r"os\.system\s*\(|subprocess\.call\s*\(|subprocess\.run\s*\(|subprocess\.Popen\s*\(|os\.popen\s*\(|commands\.getstatusoutput\s*\(",
                "Shell Injection": r"shell\s*=\s*True",
                "SQL Injection": r"cursor\.execute\s*\(.*%|\.execute\s*\(.*\+|text\s*\(.*['\"]\%.*['\"]",
                "Path Traversal": r"open\s*\([^\)]*request\.[^\)]+\)|file\s*\([^\)]*request\.[^\)]+\)", # Only flag if request data is involved,
                "Pickle Deserialization": r"pickle\.loads?\s*\(|cPickle\.loads?\s*\(",
                "YAML Unsafe Load": r"yaml\.load\s*\([^,)]*\)(?!.*Loader)",
                "Jinja2 SSTI": r"render_template_string\s*\(|environment\.from_string",
                "Insecure Random": r"random\.random\s*\(|random\.randint\s*\(",
                "Hardcoded Password": r"password\s*=\s*['\"][^'\"]+['\"]|pass\s*=\s*['\"][^'\"]+['\"]|secret\s*=\s*['\"][^'\"]+['\"]",
                "Debug Mode Enabled": r"DEBUG\s*=\s*True|debug\s*=\s*True|app\.run\s*\(.*debug\s*=\s*True",
                "Assert Used in Production": r"assert\s+",
                "Insecure Temp File": r"mktemp\s*\(|tempfile\.mktemp\s*\(",
                "Insecure Hash": r"hashlib\.md5\s*\(|hashlib\.sha1\s*\(",
            },
            "java": {
                "Runtime.exec() Injection": r"Runtime\.getRuntime\(\)\.exec\s*\(",
                "ProcessBuilder Injection": r"new\s+ProcessBuilder\s*\(",
                "SQL Injection": r"Statement\.execute\s*\(.*\+|executeQuery\s*\(.*\+",
                "Path Traversal": r"new\s+File\s*\(.*\+",
                "Deserialization": r"ObjectInputStream.*readObject\s*\(",
                "XXE Vulnerability": r"DocumentBuilderFactory|SAXParserFactory",
                "Insecure Random": r"new\s+Random\s*\(\)|Math\.random\s*\(",
                "Weak Crypto": r"DES|RC4|MD5|SHA1(?!-)",
                "Trust All Certificates": r"TrustManager|HostnameVerifier",
                "Spring Actuator Exposure": r"management\.endpoints\.web\.exposure\.include\s*=\s*['\"]\*['\"]",
            },
            "go": {
                "Command Injection": r"exec\.Command\s*\(.*\+",
                "SQL Injection": r"db\.Query\s*\(.*\+|db\.Exec\s*\(.*\+",
                "Path Traversal": r"os\.Open\s*\(.*\+|ioutil\.ReadFile\s*\(.*\+",
                "Weak Random": r"rand\.Int\s*\(|math/rand",
                "Insecure TLS": r"InsecureSkipVerify\s*:\s*true",
                "Goroutine Leak": r"go\s+func\s*\(",
                "Unsafe Pointer": r"unsafe\.Pointer",
            },
            "php": {
                "Dangerous eval()": r"\beval\s*\(",
                "Command Injection": r"\bexec\s*\(|\bsystem\s*\(|shell_exec\s*\(|passthru\s*\(",
                "SQL Injection": r"mysql_query\s*\(.*\$|mysqli_query\s*\(.*\$",
                "File Inclusion": r"include\s*\(.*\$|require\s*\(.*\$",
                "Deserialization": r"unserialize\s*\(",
                "XSS": r"echo\s+\$|print\s+\$",
            },
            "c": {
                "Buffer Overflow (strcpy)": r"\bstrcpy\s*\(",
                "Buffer Overflow (strcat)": r"\bstrcat\s*\(",
                "Buffer Overflow (sprintf)": r"\bsprintf\s*\(",
                "Buffer Overflow (gets)": r"\bgets\s*\(",
                "Buffer Overflow (memcpy)": r"\bmemcpy\s*\(",
                "Format String": r"printf\s*\([^,\"]*\)",
                "Memory Leak": r"malloc\s*\([^)]+\)(?!.*free)",
                "Use After Free": r"free\s*\([^)]+\);[^}]*\*",
                "Double Free": r"free\s*\([^)]+\);[^}]*free\s*\(",
                "Command Injection": r"\bsystem\s*\(|\bpopen\s*\(|\bexecl\s*\(|\bexecv\s*\(",
                "Hardcoded Credentials": r"password\s*=\s*\"[^\"]+\"",
                "Weak Random": r"\brand\s*\(|\bsrand\s*\(",
                "Insecure Functions": r"\bscanf\s*\(|\bgets\s*\(",
            },
            "cpp": {
                "Buffer Overflow": r"\bstrcpy\s*\(|\bstrcat\s*\(|\bsprintf\s*\(",
                "Memory Leak": r"new\s+\w+(?!.*delete)|malloc\s*\((?!.*free)",
                "Use After Free": r"delete\s+\w+;[^}]*\*\w+",
                "Command Injection": r"\bsystem\s*\(|\bpopen\s*\(",
                "Unsafe Cast": r"reinterpret_cast\s*<|const_cast\s*<",
            },
            "csharp": {
                "SQL Injection": r"SqlCommand\s*\(.*\+|ExecuteReader\s*\(.*\+",
                "Command Injection": r"Process\.Start\s*\(.*\+",
                "Deserialization": r"BinaryFormatter\.Deserialize\s*\(",
                "XSS": r"Response\.Write\s*\(.*\+|Html\.Raw\s*\(",
                "Unsafe Block": r"unsafe\s*\{",
            },
            "ruby": {
                "Command Injection": r"\bsystem\s*\(|\bexec\s*\(|`[^`]*`",
                "SQL Injection": r"find_by_sql\s*\(.*\+|where\s*\(.*#\{",
                "Code Injection": r"\beval\s*\(|instance_eval\s*\(",
                "Deserialization": r"Marshal\.load\s*\(|YAML\.load\s*\(",
            },
            "rust": {
                "Unsafe Block": r"unsafe\s*\{",
                "Memory Leak": r"Box::leak\s*\(",
                "Command Injection": r"Command::new\s*\(.*\+",
                "Panic in Library": r"unwrap\s*\(\)",
            },
            "swift": {
                "Command Injection": r"Process\s*\(\)\.launch",
                "SQL Injection": r"sqlite3_exec\s*\(.*\+",
                "Force Unwrapping": r"!\s*$|!\.",
            },
            "kotlin": {
                "SQL Injection": r"rawQuery\s*\(.*\+",
                "Command Injection": r"Runtime\.getRuntime\(\)\.exec\s*\(",
            },
            "sql": {
                "Dynamic SQL": r"EXECUTE\s+IMMEDIATE|sp_executesql",
                "Privilege Escalation": r"GRANT\s+ALL|WITH\s+GRANT\s+OPTION",
            },
            "shell": {
                "Command Injection": r"\$\([^)]+\)|`[^`]+`|\beval\s+",
                "Path Traversal": r"\.\./",
                "World Writable": r"chmod\s+777|chmod\s+666",
                "Hardcoded Credentials": r"password=|PASSWORD=",
            },
            # --- NEW INFRASTRUCTURE SUPPORT ---
            "dockerfile": {
                "Runs as Root": r"USER\s+root",
                "Missing User Instruction": r"^(?!.*USER).+$", # Heuristic/complex for regex
                "Use of ADD instead of COPY": r"^ADD\s+",
                "Sudo Usage": r"sudo\s+",
                "Use of 'latest' tag": r":latest",
                "Exposed SSH Port": r"EXPOSE\s+22",
                "Secrets in ENV": r"ENV\s+(PASSWORD|SECRET|KEY|TOKEN)",
            },
            "terraform": {
                "Open Security Group": r"cidr_blocks\s*=\s*\[\"0.0.0.0/0\"\]",
                "Public S3 Bucket": r"acl\s*=\s*\"public-read\"",
                "Unencrypted Storage": r"encrypted\s*=\s*false",
                "Hardcoded Secret": r"(secret|key|password)\s*=\s*\"[^\"]+\"",
            },
            "yaml": {
                "Privileged Container": r"privileged:\s*true",
                "Host Network Access": r"hostNetwork:\s*true",
                "Run as Root": r"runAsUser:\s*0",
                "Missing CPU/Memory Limits": r"resources:\s*\{\}", 
                "Docker Socket Mount": r"path:\s*/var/run/docker.sock",
            }
        }



    def detect_language(self, filename: str, code: str = "") -> str:
        """Detect programming language from filename extension"""
        ext_map = {
            # Low-level / Systems
            ".py": "python", ".pyw": "python",
            ".c": "c", ".h": "c", 
            ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp",
            ".rs": "rust",
            ".go": "go",
            
            # Java / JVM
            ".java": "java", ".jar": "java",
            ".kt": "kotlin", ".kts": "kotlin",
            ".scala": "java", # Fallback to Java rules
            
            # Web
            ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
            ".ts": "typescript", ".tsx": "typescript",
            ".vue": "javascript", ".svelte": "javascript", # Treat as JS for regex scan
            ".php": "php",
            ".rb": "ruby", ".erb": "ruby",
            
            # Mobile
            ".swift": "swift",
            ".cs": "csharp",
            
            # Shell
            ".sh": "shell", ".bash": "shell", ".zsh": "shell",
            ".bat": "shell", ".ps1": "shell", # Treat Windows shell as shell for now
            
            # Data / Config (Infrastructure)
            ".sql": "sql", 
            ".tf": "terraform", ".hcl": "terraform",
            ".yaml": "yaml", ".yml": "yaml",
            ".dockerfile": "dockerfile",
            ".json": "json",
            ".xml": "xml"
        }
        import os
        filename_lower = filename.lower()
        if filename_lower == "dockerfile" or filename_lower.endswith(".dockerfile"):
            return "dockerfile"
            
        ext = os.path.splitext(filename)[1].lower()
        return ext_map.get(ext, "unknown")

    def analyze(self, code: str, filename: str = "unknown") -> Dict[str, Any]:
        """Main analysis entry point"""
        lang = self.detect_language(filename, code)
        findings = []
        lines = code.split('\n')
        
        # Pass 1: Secret detection (all languages)
        for i, line in enumerate(lines):
            for pattern in self.SECRETS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        "type": "Hardcoded Secret",
                        "cwe": "CWE-798",
                        "severity": "High",
                        "location": {"line": i + 1, "code": line.strip()[:100]},
                        "reason": "Hardcoded credentials or secrets detected in source code",
                        "recommendation": "Use environment variables or secure credential management"
                    })
                    break
        
        # Pass 2: Bug patterns (all languages)
        detected_bug_lines = set()
        for bug_type, patterns in self.BUGS.items():
            if not self._is_relevant_bug(bug_type, lang):
                continue
                
            for pattern in patterns:
                for i, line in enumerate(lines):
                    if re.search(pattern, line) and (i + 1, bug_type) not in detected_bug_lines:
                        findings.append({
                            "type": bug_type,
                            "cwe": self._get_bug_cwe(bug_type),
                            "severity": self._get_bug_severity(bug_type),
                            "location": {"line": i + 1, "code": line.strip()[:100]},
                            "reason": f"Potential {bug_type.lower()} detected",
                            "recommendation": self._get_bug_recommendation(bug_type)
                        })
                        detected_bug_lines.add((i + 1, bug_type))
        
        # Pass 3: Taint analysis (source -> sink)
        if lang in self.SOURCES and lang in self.SINKS:
            source_lines = set()
            for pattern in self.SOURCES[lang]:
                for i, line in enumerate(lines):
                    if re.search(pattern, line):
                        source_lines.add(i)
            
            for vuln_type, sink_patterns in self.SINKS[lang].items():
                for pattern in sink_patterns:
                    for i, line in enumerate(lines):
                        if re.search(pattern, line):
                            # Check if there's a source nearby (within 20 lines)
                            has_nearby_source = any(abs(i - s) <= 20 for s in source_lines)
                            if has_nearby_source or self._has_user_input_indicator(line):
                                findings.append({
                                    "type": vuln_type,
                                    "cwe": self._get_vuln_cwe(vuln_type),
                                    "severity": "High",
                                    "location": {"line": i + 1, "code": line.strip()[:100]},
                                    "reason": f"Potential {vuln_type} - user input may reach dangerous sink",
                                    "recommendation": self._get_vuln_recommendation(vuln_type)
                                })
        
        # Pass 4: Language-specific dangerous patterns
        if lang in self.LANG_DANGEROUS:
            detected_lines = set()
            for i, line in enumerate(lines):
                if i + 1 in detected_lines:
                    continue
                for vuln_name, pattern in self.LANG_DANGEROUS[lang].items():
                    if re.search(pattern, line, re.IGNORECASE):
                        already_found = any(
                            f.get('location', {}).get('line') == i + 1 and f.get('type') == vuln_name
                            for f in findings
                        )
                        if not already_found:
                            findings.append({
                                "type": vuln_name,
                                "cwe": self._map_lang_cwe(vuln_name),
                                "severity": self._get_lang_severity(vuln_name),
                                "location": {"line": i + 1, "code": line.strip()[:100]},
                                "reason": self._get_lang_reason(vuln_name),
                                "recommendation": self._get_lang_recommendation(vuln_name)
                            })
                            detected_lines.add(i + 1)
        
        return {
            "language": lang,
            "findings": findings,
            "summary": {
                "total": len(findings),
                "critical": sum(1 for f in findings if f["severity"] == "Critical"),
                "high": sum(1 for f in findings if f["severity"] == "High"),
                "medium": sum(1 for f in findings if f["severity"] == "Medium"),
                "low": sum(1 for f in findings if f["severity"] == "Low"),
            }
        }

    def _has_user_input_indicator(self, line: str) -> bool:
        indicators = ["input", "request", "param", "query", "form", "body", "args", "argv", "user"]
        return any(ind in line.lower() for ind in indicators)

    def _get_bug_cwe(self, bug_type: str) -> str:
        cwe_map = {
            # Memory & Pointer Bugs
            "Null Pointer Dereference": "CWE-476",
            "Uninitialized Variable": "CWE-457",
            "Use After Free": "CWE-416",
            "Double Free": "CWE-415",
            "Memory Leak": "CWE-401",
            # Arithmetic Bugs
            "Division by Zero": "CWE-369",
            "Integer Overflow": "CWE-190",
            "Off-by-One Error": "CWE-193",
            # Control Flow Bugs
            "Infinite Loop": "CWE-835",
            "Infinite Recursion": "CWE-674",
            "Unreachable Code": "CWE-561",
            # Resource Bugs
            "Resource Leak": "CWE-404",
            "Unchecked Return Value": "CWE-252",
            "File Descriptor Leak": "CWE-775",
            # Concurrency Bugs
            "Race Condition": "CWE-362",
            "Deadlock Risk": "CWE-833",
            # Type Bugs
            "Type Confusion": "CWE-843",
            "Signed/Unsigned Mismatch": "CWE-195",
            # Input Validation Bugs
            "Missing Input Validation": "CWE-20",
            "Array Index Out of Bounds": "CWE-129",
            # Deprecated/Unsafe Functions
            "Deprecated Function (gets)": "CWE-676",
            "Deprecated Function (tmpnam)": "CWE-377",
            "Unsafe Function (strcpy)": "CWE-120",
            "Unsafe Function (sprintf)": "CWE-120",
        }
        return cwe_map.get(bug_type, "CWE-000")

    def _get_bug_severity(self, bug_type: str) -> str:
        critical = ["Use After Free", "Double Free", "Null Pointer Dereference", "Buffer Overflow"]
        high = ["Memory Leak", "Integer Overflow", "Race Condition", "Unsafe Function", "Deprecated Function"]
        for pattern in critical:
            if pattern.lower() in bug_type.lower():
                return "Critical"
        for pattern in high:
            if pattern.lower() in bug_type.lower():
                return "High"
        return "Medium"

    def _get_bug_recommendation(self, bug_type: str) -> str:
        recs = {
            # Memory & Pointer Bugs
            "Null Pointer Dereference": "Add null checks before dereferencing pointers",
            "Uninitialized Variable": "Initialize all variables before use",
            "Use After Free": "Set pointers to NULL after freeing and avoid reuse",
            "Double Free": "Track allocation state or set pointer to NULL after free",
            "Memory Leak": "Ensure all allocated memory is freed; use RAII in C++",
            # Arithmetic Bugs
            "Division by Zero": "Validate divisor is non-zero before division",
            "Integer Overflow": "Use safe integer arithmetic or check bounds before operations",
            "Off-by-One Error": "Use < instead of <= in loop conditions; verify array bounds",
            # Control Flow Bugs
            "Infinite Loop": "Ensure loop has proper exit condition",
            "Infinite Recursion": "Add base case to recursive function",
            "Unreachable Code": "Remove dead code or fix control flow logic",
            # Resource Bugs
            "Resource Leak": "Close all opened resources in finally block or use RAII",
            "Unchecked Return Value": "Always check return values of functions that can fail",
            "File Descriptor Leak": "Close file descriptors when done; use RAII wrappers",
            # Concurrency Bugs
            "Race Condition": "Use proper synchronization (mutex, semaphore, atomic operations)",
            "Deadlock Risk": "Use consistent lock ordering; avoid nested locks",
            # Type Bugs
            "Type Confusion": "Use proper type casting; avoid void* when possible",
            "Signed/Unsigned Mismatch": "Use consistent types; be explicit about signedness",
            # Input Validation Bugs
            "Missing Input Validation": "Validate all user input before use",
            "Array Index Out of Bounds": "Check array bounds before access",
            # Deprecated/Unsafe Functions
            "Deprecated Function (gets)": "Use fgets() with explicit buffer size instead",
            "Deprecated Function (tmpnam)": "Use mkstemp() for secure temporary files",
            "Unsafe Function (strcpy)": "Use strncpy() or strlcpy() with bounds checking",
            "Unsafe Function (sprintf)": "Use snprintf() with buffer size limit",
        }
        return recs.get(bug_type, "Review and fix the issue")

    def _get_vuln_cwe(self, vuln_type: str) -> str:
        cwe_map = {
            "SQL Injection": "CWE-89",
            "Command Injection": "CWE-78",
            "Path Traversal": "CWE-22",
            "XSS": "CWE-79",
            "Deserialization": "CWE-502",
            "SSRF": "CWE-918",
        }
        return cwe_map.get(vuln_type, "CWE-000")

    def _get_vuln_recommendation(self, vuln_type: str) -> str:
        recs = {
            "SQL Injection": "Use parameterized queries or prepared statements",
            "Command Injection": "Validate input and use safe APIs instead of shell commands",
            "Path Traversal": "Validate and sanitize file paths, use allowlists",
            "XSS": "Sanitize output and use Content Security Policy",
            "Deserialization": "Validate serialized data and use safe formats like JSON",
            "SSRF": "Validate and allowlist URLs, block internal network access",
        }
        return recs.get(vuln_type, "Review and fix the security issue")

    def _map_lang_cwe(self, vuln_name: str) -> str:
        cwe_map = {
            # Code Injection
            "Dangerous eval()": "CWE-95", "Dangerous exec()": "CWE-95",
            "Dangerous Function constructor": "CWE-95",
            "Dangerous setTimeout with string": "CWE-95",
            "Dangerous setInterval with string": "CWE-95",
            "Code Injection": "CWE-94",
            # XSS
            "Dangerous innerHTML": "CWE-79", "Dangerous document.write()": "CWE-79",
            "jQuery HTML Injection": "CWE-79", "XSS": "CWE-79",
            # Command Injection
            "Command Injection": "CWE-78", "OS Command Injection": "CWE-78",
            "Shell Injection": "CWE-78", "Runtime.exec() Injection": "CWE-78",
            "ProcessBuilder Injection": "CWE-78",
            # SQL Injection
            "SQL Injection": "CWE-89", "Dynamic SQL": "CWE-89",
            # Path Traversal
            "Path Traversal": "CWE-22", "File Inclusion": "CWE-98",
            # Memory Safety
            "Buffer Overflow (strcpy)": "CWE-120", "Buffer Overflow (strcat)": "CWE-120",
            "Buffer Overflow (sprintf)": "CWE-120", "Buffer Overflow (gets)": "CWE-120",
            "Memory Leak": "CWE-401", "Use After Free": "CWE-416",
            "Double Free": "CWE-415", "Double Delete": "CWE-415",
            "Format String": "CWE-134",
            # Deserialization
            "Deserialization": "CWE-502", "Pickle Deserialization": "CWE-502",
            "YAML Unsafe Load": "CWE-502",
            # Crypto
            "Weak Crypto": "CWE-327", "Insecure Crypto": "CWE-327",
            "Insecure Hash": "CWE-328", "Weak Random": "CWE-338",
            "Insecure Random": "CWE-338",
            # Auth/Secrets
            "Hardcoded Credentials": "CWE-798", "Hardcoded Password": "CWE-798",
            # Network
            "Insecure HTTP Fetch": "CWE-319", "HTTP without TLS": "CWE-319",
            "Insecure WebSocket": "CWE-319", "Insecure Network": "CWE-319",
            "Insecure TLS": "CWE-295", "Trust All Certificates": "CWE-295",
            "Insecure CORS": "CWE-942",
            # Other
            "Open Redirect": "CWE-601", "Prototype Pollution": "CWE-1321",
            "XXE Vulnerability": "CWE-611", "XXE": "CWE-611",
            "LDAP Injection": "CWE-90", "Template Injection": "CWE-1336",
            "Reflection Abuse": "CWE-470", "Unsafe Block": "CWE-787",
            "Force Unwrapping": "CWE-476", "Panic in Library": "CWE-248",
            "Unsafe Cast": "CWE-704", "Race Condition": "CWE-362",
            "Mass Assignment": "CWE-915", "Debug Mode": "CWE-489",
            "Insecure Cookie": "CWE-614", "Insecure LocalStorage": "CWE-922",
            "Insecure SessionStorage": "CWE-922", "Iframe Injection": "CWE-1021",
            "JSONP Callback": "CWE-352", "Type Assertion Bypass": "CWE-843",
            "Privilege Escalation": "CWE-269", "Dangerous DROP": "CWE-1321",
            "World Writable": "CWE-732", "WebView JavaScript": "CWE-749",
            "Insecure Functions": "CWE-676",
        }
        return cwe_map.get(vuln_name, "CWE-000")

    def _get_lang_severity(self, vuln_name: str) -> str:
        critical = ["Buffer Overflow", "Use After Free", "Double Free", "Command Injection",
                    "SQL Injection", "eval", "exec", "Deserialization", "XXE"]
        high = ["XSS", "innerHTML", "document.write", "Path Traversal", "Code Injection",
                "Shell Injection", "Template Injection", "LDAP Injection", "File Inclusion"]
        for pattern in critical:
            if pattern.lower() in vuln_name.lower():
                return "Critical"
        for pattern in high:
            if pattern.lower() in vuln_name.lower():
                return "High"
        return "Medium"

    def _get_lang_reason(self, vuln_name: str) -> str:
        reasons = {
            "Dangerous eval()": "eval() executes arbitrary code and enables injection attacks",
            "Dangerous exec()": "exec() executes arbitrary code and enables injection attacks",
            "Dangerous innerHTML": "innerHTML can execute embedded scripts leading to XSS",
            "Dangerous document.write()": "document.write() can inject malicious HTML/scripts",
            "SQL Injection": "Unsanitized input in SQL queries can compromise the database",
            "Command Injection": "Unsanitized input in system commands enables code execution",
            "Path Traversal": "Unsanitized file paths can allow access to unauthorized files",
            "Buffer Overflow (strcpy)": "strcpy() doesn't check buffer bounds, enabling overflow",
            "Buffer Overflow (gets)": "gets() is inherently unsafe and should never be used",
            "Memory Leak": "Unreleased memory can lead to denial of service",
            "Use After Free": "Accessing freed memory can lead to crashes or code execution",
            "Hardcoded Credentials": "Hardcoded secrets in source code are easily discoverable",
            "Weak Random": "Predictable random numbers can compromise security",
            "Open Redirect": "Unvalidated redirects can be used for phishing attacks",
            "Prototype Pollution": "Modifying object prototypes can affect application behavior",
            "Unsafe Block": "Unsafe Rust code bypasses memory safety guarantees",
            "Force Unwrapping": "Force unwrapping optionals can cause runtime crashes",
            "Debug Mode": "Debug mode may expose sensitive information in production",
        }
        if vuln_name in reasons:
            return reasons[vuln_name]
        for key, reason in reasons.items():
            if key.lower() in vuln_name.lower():
                return reason
        return f"Potential security vulnerability: {vuln_name}"

    def _get_lang_recommendation(self, vuln_name: str) -> str:
        recs = {
            "Dangerous eval()": "Use JSON.parse() for data or ast.literal_eval() in Python",
            "Dangerous exec()": "Avoid dynamic code execution; use predefined functions",
            "Dangerous innerHTML": "Use textContent for text or sanitize HTML with DOMPurify",
            "SQL Injection": "Use parameterized queries or prepared statements",
            "Command Injection": "Validate input and use safe APIs instead of shell commands",
            "Path Traversal": "Validate file paths and use allowlists",
            "Buffer Overflow (strcpy)": "Use strncpy() or strlcpy() with proper bounds checking",
            "Buffer Overflow (gets)": "Use fgets() with explicit buffer size",
            "Memory Leak": "Ensure all allocated memory is properly freed",
            "Use After Free": "Set pointers to NULL after freeing",
            "Hardcoded Credentials": "Use environment variables or secure credential management",
            "Weak Random": "Use cryptographically secure random number generators",
            "Open Redirect": "Validate redirect URLs against an allowlist",
            "Prototype Pollution": "Use Object.create(null) or validate JSON input",
            "Unsafe Block": "Minimize unsafe code and document safety invariants",
            "Force Unwrapping": "Use optional binding (if let) or nil coalescing",
            "Debug Mode": "Disable debug mode in production environments",
        }
        if vuln_name in recs:
            return recs[vuln_name]
        for key, rec in recs.items():
            if key.lower() in vuln_name.lower():
                return rec
        return f"Review and fix the {vuln_name.lower()} vulnerability"
