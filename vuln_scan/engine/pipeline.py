"""
Dual-LLM Pipeline Orchestrator
Manages the Phase 1 (Planning) and Phase 2 (Deep Analysis) workflow.
"""

import sys
import os
import json
import logging
from typing import Dict, Any, List, Optional
from pathlib import Path

# Add project root to path to import providers
sys.path.append(str(Path(__file__).parent.parent))

from engine.parsers import CodeParser
from engine.semantic import SemanticAnalyzer
from engine.filters import KeywordFilter
from engine.prompts import PHASE_1_PROMPT, PHASE_2_PROMPT
from engine.ai_malicious_detection import AIMaliciousDetector

# Try to import providers, handle failure gracefully
try:
    from providers import load_provider, GeminiProvider, GroqProvider, OpenAIProvider, ClaudeProvider
    HAS_PROVIDERS = True
except ImportError:
    HAS_PROVIDERS = False

class SecurityPipeline:
    """
    Orchestrates the security scanning pipeline.
    """
    
    def __init__(self):
        self.parser = CodeParser()
        self.semantic = SemanticAnalyzer()
        self.filter = KeywordFilter()
        self.ai_detector = AIMaliciousDetector()  # AI malicious code detector
        self.logger = logging.getLogger("vuln_scan")
        
        # Initialize providers
        self.phase1_provider = self._get_phase1_provider()
        self.phase2_provider = self._get_phase2_provider()

    def _get_phase1_provider(self):
        """Get fast provider for Phase 1 (Groq preferred)"""
        if not HAS_PROVIDERS: return None
        
        if os.getenv("GROQ_KEY"):
            return GroqProvider()
        elif os.getenv("OPENAI_API_KEY"):
            return OpenAIProvider(model="gpt-3.5-turbo")
        elif os.getenv("GOOGLE_API_KEY"):
            return GeminiProvider(model="gemini-1.5-flash")
        return None

    def _get_phase2_provider(self):
        """Get strong provider for Phase 2 (Gemini/Claude/GPT-4)"""
        if not HAS_PROVIDERS: return None
        
        if os.getenv("GOOGLE_API_KEY"):
            return GeminiProvider(model="gemini-1.5-pro")
        elif os.getenv("ANTHROPIC_API_KEY"):
            return ClaudeProvider()
        elif os.getenv("OPENAI_API_KEY"):
            return OpenAIProvider(model="gpt-4")
        return None

    def scan_file(self, file_path: str, mode: str = "hybrid") -> Dict[str, Any]:
        """
        Run the scanning pipeline on a file.
        """
        self.logger.info(f"Scanning file: {file_path} in mode: {mode}")
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                code = f.read()
            self.logger.info(f"Read {len(code)} bytes")
        except Exception as e:
            self.logger.error(f"File read error: {e}")
            return {"status": "ERROR", "error": str(e)}

        # 1. Keyword Filtering (Pre-screen)
        if mode != 'deep':
            self.logger.info("Running Keyword Filter...")
            is_suspicious, categories, risk_score = self.filter.scan(code)
            self.logger.info(f"Filter result: suspicious={is_suspicious}, score={risk_score}")
            
            if not is_suspicious and mode != 'fast':
                return {
                    "status": "SAFE",
                    "reason": "No suspicious patterns found by keyword filter.",
                    "risk_score": risk_score,
                    "findings": []
                }
        else:
            categories = []
            risk_score = 100 

        # 2. Parsing & Structural Analysis
        self.logger.info("Running Parser...")
        structure = self.parser.parse(code, file_path)
        
        # 3. Semantic Analysis
        self.logger.info("Running Semantic Analysis...")
        semantic_result = self.semantic.analyze(code, file_path)
        semantic_findings = semantic_result.get('findings', []) if isinstance(semantic_result, dict) else semantic_result
        self.logger.info(f"Found {len(semantic_findings)} semantic hints")
        
        if mode == 'fast':
            status = "VULNERABLE" if semantic_findings else "SAFE"
            # Run AI malicious detection
            ai_scan = self.ai_detector.run_full_ai_malicious_scan(code)
            self.logger.info(f"AI scan complete: {ai_scan['risk_level']}")
            return {
                "status": status,
                "reason": "Fast scan completed (Local Analysis only).",
                "risk_score": risk_score,
                "findings": semantic_findings,
                "semantic_hints": semantic_findings,
                "ai_malicious_risk": ai_scan
            }

        # 4. Phase 1: Scan Planning (LLM)
        if not self.phase1_provider:
            self.logger.warning("No Phase 1 provider available, using local analysis only")
            # Return semantic findings without LLM analysis
            status = "VULNERABLE" if semantic_findings else "SAFE"
            # Run AI malicious detection
            ai_scan = self.ai_detector.run_full_ai_malicious_scan(code)
            self.logger.info(f"AI scan complete: {ai_scan['risk_level']}")
            return {
                "status": status,
                "reason": "Local analysis completed (No LLM provider configured).",
                "risk_score": risk_score,
                "findings": semantic_findings,
                "semantic_hints": semantic_findings,
                "categories": categories,
                "ai_malicious_risk": ai_scan
            }

        self.logger.info("Starting Phase 1 (Planning)...")
        plan = self._run_phase1(code, structure, categories, semantic_findings)
        self.logger.info(f"Phase 1 complete. Risk Level: {plan.get('risk_level')}")
        
        if plan.get("risk_level") in ["SAFE", "LOW"] and mode != 'deep':
            # Run AI malicious detection even on safe code
            ai_scan = self.ai_detector.run_full_ai_malicious_scan(code)
            self.logger.info(f"AI scan complete: {ai_scan['risk_level']}")
            return {
                "status": "SAFE", 
                "plan": plan,
                "risk_score": risk_score,
                "findings": [],
                "ai_malicious_risk": ai_scan
            }

        # 5. Phase 2: Deep Analysis (LLM)
        if not self.phase2_provider:
            self.phase2_provider = self.phase1_provider

        self.logger.info("Starting Phase 2 (Deep Analysis)...")
        report = self._run_phase2(code, plan, semantic_findings)
        self.logger.info("Phase 2 complete")
        
        # Run AI malicious detection after normal scan
        ai_scan = self.ai_detector.run_full_ai_malicious_scan(code)
        self.logger.info(f"AI malicious scan complete: {ai_scan['risk_level']}")
        
        return {
            "status": report.get("status", "UNKNOWN"),
            "findings": report.get("findings", []),
            "plan": plan,
            "semantic_hints": semantic_findings,
            "ai_malicious_risk": ai_scan
        }

    def _run_phase1(self, code: str, structure: Dict, categories: List[str], semantic_findings: List[Dict]) -> Dict:
        """Execute Phase 1: Planning"""
        # Create a summary context for the LLM
        summary = f"""
        Categories Found: {', '.join(categories)}
        Functions: {len(structure.get('functions', []))}
        Imports: {len(structure.get('imports', []))}
        Potential Semantic Issues: {len(semantic_findings)}
        """
        
        # Truncate code for Phase 1 if too large (focus on structure)
        context = f"METADATA:\n{summary}\n\nCODE SUMMARY:\n{code[:8000]}" 
        
        try:
            response = self.phase1_provider.ask(
                system_prompt=PHASE_1_PROMPT,
                user_prompt="Analyze this file and generate a Scan Plan.",
                context=context
            )
            return self._parse_json_response(response)
        except Exception as e:
            self.logger.error(f"Phase 1 failed: {e}")
            return {"risk_level": "UNKNOWN", "error": str(e)}

    def _run_phase2(self, code: str, plan: Dict, semantic_findings: List[Dict]) -> Dict:
        """Execute Phase 2: Deep Analysis"""
        
        # Focus on critical functions identified in Phase 1
        critical_funcs = plan.get("critical_functions", [])
        focus_areas = plan.get("focus_areas", [])
        
        context = f"""
        PHASE 1 PLAN:
        Risk Level: {plan.get('risk_level')}
        Focus Areas: {json.dumps(focus_areas)}
        
        SEMANTIC HINTS:
        {json.dumps(semantic_findings)}
        
        FULL CODE:
        {code}
        """
        
        try:
            response = self.phase2_provider.ask(
                system_prompt=PHASE_2_PROMPT,
                user_prompt="Perform deep vulnerability analysis based on the plan.",
                context=context
            )
            return self._parse_json_response(response)
        except Exception as e:
            self.logger.error(f"Phase 2 failed: {e}")
            return {"status": "ERROR", "error": str(e)}

    def _parse_json_response(self, response: str) -> Dict:
        """Extract and parse JSON from LLM response"""
        try:
            # Try standard json first
            import json_repair
            return json_repair.loads(response)
        except Exception:
            try:
                # Fallback to standard json extraction
                if "```json" in response:
                    start = response.find("```json") + 7
                    end = response.find("```", start)
                    json_str = response[start:end].strip()
                elif "```" in response:
                    start = response.find("```") + 3
                    end = response.find("```", start)
                    json_str = response[start:end].strip()
                else:
                    json_str = response.strip()
                    
                return json.loads(json_str)
            except Exception as e:
                # Fallback: return raw text wrapped in dict
                print(f"[DEBUG] JSON Parse Error: {e}")
                print(f"[DEBUG] Raw Response: {response[:500]}...") 
                return {"raw_response": response, "error": "Failed to parse JSON"}
