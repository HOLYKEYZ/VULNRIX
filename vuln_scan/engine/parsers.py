"""
Universal Code Parser (Tree-sitter + Regex Fallback)
Supports: Python, JavaScript, TypeScript, Java, Go, PHP, C/C++, Ruby, Rust
"""

import os
import re
import logging
from typing import Dict, Any, List, Optional

# Configure logging
logger = logging.getLogger("vuln_scan")

try:
    from tree_sitter import Language, Parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False
    logger.warning("Tree-sitter not installed. Falling back to Regex.")

class CodeParser:
    """
    Universal parser that tries Tree-sitter first, then Regex.
    """
    
    def __init__(self):
        self.parsers = {}
        if HAS_TREE_SITTER:
            self._init_tree_sitter()

    def _init_tree_sitter(self):
        """Initialize Tree-sitter parsers for supported languages"""
        try:
            from tree_sitter import Language, Parser
            import tree_sitter_python as tspython
            import tree_sitter_javascript as tsjs
            
            # Initialize parsers
            self.ts_parsers = {}
            
            # Python
            py_parser = Parser()
            py_parser.set_language(Language(tspython.language()))
            self.ts_parsers['python'] = py_parser
            
            # JavaScript
            js_parser = Parser()
            js_parser.set_language(Language(tsjs.language()))
            self.ts_parsers['javascript'] = js_parser
            
            # Add other languages if their packages are available
            try:
                import tree_sitter_go as tsgo
                go_parser = Parser()
                go_parser.set_language(Language(tsgo.language()))
                self.ts_parsers['go'] = go_parser
            except ImportError:
                pass
                
        except Exception as e:
            logger.warning(f"Failed to initialize Tree-sitter: {e}")
            self.ts_parsers = {}

    def parse(self, code: str, file_path: str) -> Dict[str, Any]:
        """
        Parse code and return structural metadata.
        """
        ext = os.path.splitext(file_path)[1].lower()
        lang = self._get_lang_from_ext(ext)
        
        # 1. Try Tree-sitter (if available and language loaded)
        if hasattr(self, 'ts_parsers') and lang in self.ts_parsers:
            try:
                return self._parse_tree_sitter(code, lang)
            except Exception as e:
                logger.error(f"Tree-sitter parse failed for {lang}: {e}")
                # Fall through to Regex
        
        # 2. Fallback to Regex
        return self._parse_regex(code, ext)

    def _parse_tree_sitter(self, code: str, lang: str) -> Dict[str, Any]:
        """
        Parse with tree-sitter for proper AST extraction.
        """
        structure = {
            "functions": [],
            "classes": [],
            "imports": [],
            "comments": []
        }
        
        parser = self.ts_parsers.get(lang)
        tree = parser.parse(bytes(code, 'utf8'))
        
        # Recursive AST traversal
        def traverse(node):
            if node.type == 'function_definition' or node.type == 'method_definition':
                # Python/JS function
                name_node = node.child_by_field_name('name')
                if name_node:
                    structure["functions"].append(code[name_node.start_byte:name_node.end_byte])
            elif node.type == 'class_definition':
                # Python/JS class
                name_node = node.child_by_field_name('name')
                if name_node:
                    structure["classes"].append(code[name_node.start_byte:name_node.end_byte])
            elif node.type == 'import_statement' or node.type == 'import_from_statement':
                # Python imports
                structure["imports"].append(code[node.start_byte:node.end_byte])
            
            for child in node.children:
                traverse(child)
                
        traverse(tree.root_node)
        return structure

    def _parse_regex(self, code: str, ext: str) -> Dict[str, Any]:
        """
        Regex-based parsing fallback.
        """
        structure = {
            "functions": [],
            "classes": [],
            "imports": [],
            "comments": []
        }
        
        # Generic patterns
        patterns = {
            "python": {
                "function": r"def\s+([a-zA-Z_][a-zA-Z0-9_]*)",
                "class": r"class\s+([a-zA-Z_][a-zA-Z0-9_]*)",
                "import": r"import\s+[\w\.]+|from\s+[\w\.]+\s+import"
            },
            "javascript": {
                "function": r"function\s+([a-zA-Z_][a-zA-Z0-9_]*)|const\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*\(?.*?\)?\s*=>",
                "class": r"class\s+([a-zA-Z_][a-zA-Z0-9_]*)",
                "import": r"import\s+.*?from|require\("
            },
            # Add more languages as needed
        }
        
        lang = self._get_lang_from_ext(ext)
        lang_patterns = patterns.get(lang, patterns["python"]) # Default to python-like
        
        # Extract functions
        for match in re.finditer(lang_patterns["function"], code):
            name = match.group(1) or match.group(2)
            if name:
                structure["functions"].append(name)
                
        # Extract imports
        for match in re.finditer(lang_patterns["import"], code):
            structure["imports"].append(match.group(0))
            
        return structure

    def _get_lang_from_ext(self, ext: str) -> str:
        map = {
            '.py': 'python',
            '.js': 'javascript', '.jsx': 'javascript', '.ts': 'javascript', '.tsx': 'javascript',
            '.java': 'java',
            '.go': 'go',
            '.php': 'php',
            '.rb': 'ruby',
            '.c': 'c', '.cpp': 'c', '.h': 'c'
        }
        return map.get(ext, 'python')
