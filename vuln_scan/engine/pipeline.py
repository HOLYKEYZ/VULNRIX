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
        elif os.getenv("GEMINI_API_KEY"):
            return GeminiProvider(model="gemini-1.5-flash")
        return None

    def _get_phase2_provider(self):
        """Get strong provider for Phase 2 (Gemini/Claude/GPT-4)"""
        if not HAS_PROVIDERS: return None
        
        if os.getenv("GEMINI_API_KEY"):
            return GeminiProvider(model="gemini-1.5-pro")
        elif os.getenv("ANTHROPIC_API_KEY"):
            return ClaudeProvider()
        elif os.getenv("OPENAI_API_KEY"):
            return OpenAIProvider(model="gpt-4")
        return None

    def scan_file(self, file_path: str, mode: str = "hybrid") -> Dict[str, Any]:
        """
        Run the scanning pipeline on a file.
        Memory-optimized for Render free tier (512MB).
        """
        self.logger.info(f"Scanning file: {file_path} in mode: {mode}")
        try:
            # File Read
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                self.logger.info(f"Read {len(code)} bytes")
            except Exception as e:
                self.logger.error(f"File read error: {e}")
                return {"status": "ERROR", "error": f"File read error: {str(e)}"}

            # Truncate code early only for LLM/Logging safety, but keep full code for analysis
            # Render Free Tier allows ~512MB RAM, so keeping 1-2MB string in memory is fine.
            # We already track file size in file_filter (MAX 200KB-1MB usually).
            
            # 1. Keyword Filtering (Fast, runs on FULL code)
            self.logger.info("Running Keyword Filter...")
            is_suspicious, categories, risk_score = self.filter.scan(code)
            self.logger.info(f"Filter result: suspicious={is_suspicious}, score={risk_score}")
            
            # 2. Parsing (Lightweight, runs on FULL code)
            self.logger.info("Running Parser...")
            structure = self.parser.parse(code, file_path)
            
            # 3. Semantic Analysis (Lightweight, runs on FULL code)
            self.logger.info("Running Semantic Analysis...")
            semantic_result = self.semantic.analyze(code, file_path)
            semantic_findings = semantic_result.get('findings', []) if isinstance(semantic_result, dict) else semantic_result
            self.logger.info(f"Found {len(semantic_findings)} semantic hints")
            
            # Create Truncated Version for LLM Context & AI Scan (if expensive)
            # AI Malicious Detector uses TF-IDF/ML, might differ performance-wise.
            # Keeping AI Detector on full code if < 100KB, else truncate? 
            # Let's keep AI Detector on full code too, it's local.
            
            # 4. AI Malicious Detection (Local, no LLM, runs on FULL code)
            ai_scan = self.ai_detector.run_full_ai_malicious_scan(code)
            self.logger.info(f"AI scan: {ai_scan.get('risk_level', 'UNKNOWN')}")

            # FAST MODE: No LLM, pure local analysis
            if mode == 'fast':
                status = "VULNERABLE" if semantic_findings else "SAFE"
                return {
                    "status": status,
                    "reason": "Fast scan completed (Local Analysis only).",
                    "risk_score": risk_score,
                    "findings": semantic_findings[:500],
                    "semantic_hints": semantic_findings[:500],
                    "ai_malicious_risk": ai_scan,
                    "categories": categories
                }

            # HYBRID MODE: Single lightweight LLM call (Phase 1 only)
            if mode == 'hybrid':
                if not self.phase1_provider:
                    status = "VULNERABLE" if semantic_findings else "SAFE"
                    return {
                        "status": status,
                        "reason": "Local analysis only (No LLM configured).",
                        "risk_score": risk_score,
                        "findings": semantic_findings[:500],
                        "ai_malicious_risk": ai_scan
                    }

                self.logger.info("Running lightweight LLM analysis...")
                # Truncate code for LLM to save tokens/memory
                truncated_code = code[:10000] 
                plan = self._run_phase1(truncated_code, structure, categories, semantic_findings[:5])
                
                if not isinstance(plan, dict):
                    plan = {"risk_level": "UNKNOWN", "error": "Invalid response"}

                is_risky = plan.get("risk_level") in ["CRITICAL", "HIGH", "MEDIUM"]
                
                # If AI says SAFE, discard regex findings to reduce false positives
                final_findings = semantic_findings[:500] if is_risky else []

                return {
                    "status": "VULNERABLE" if is_risky else "SAFE",
                    "risk_score": risk_score,
                    "findings": final_findings,
                    "plan": plan,
                    "ai_malicious_risk": ai_scan,
                    "reason": f"Hybrid scan: {plan.get('reasoning', 'Analysis complete')}"
                }

            # DEEP MODE: Full analysis but still memory-conscious
            if mode == 'deep':
                if not self.phase1_provider:
                    return {
                        "status": "ERROR",
                        "error": "Deep mode requires LLM. Configure GEMINI_API_KEY.",
                        "findings": semantic_findings[:10]
                    }

                self.logger.info("Phase 1: Planning...")
                # Truncate code for LLM to save tokens/memory
                truncated_code = code[:10000]
                plan = self._run_phase1(truncated_code, structure, categories, semantic_findings[:10])
                
                if not isinstance(plan, dict):
                    plan = {"risk_level": "UNKNOWN"}

                # Only run Phase 2 if Phase 1 found something OR if we have local findings
                # This ensures we don't skip deep analysis if regex caught something the LLM missed in the summary.
                risk_level = plan.get("risk_level", "UNKNOWN")
                has_local_findings = len(semantic_findings) > 0
                
                if risk_level in ["CRITICAL", "HIGH", "MEDIUM"] or has_local_findings:
                    self.logger.info("Phase 2: Deep Analysis (Triggered by Risk Level or Local Findings)...")
                    if not self.phase2_provider:
                        self.phase2_provider = self.phase1_provider
                    report = self._run_phase2(code, plan, semantic_findings[:20])
                    
                    if not isinstance(report, dict):
                        report = {"status": "ERROR", "findings": []}
                    
                    # Merge regex findings with LLM findings?
                    # NO: The user wants "barest minimum false positives" and "AI to scan".
                    # We pass regex as hints to AI. If AI confirms them, they are in 'report'.
                    # If AI ignores them, we trust the AI and drop them.
                    
                    llm_findings = report.get("findings", [])
                    
                    # Fallback: If AI returned NO findings but risk is HIGH, maybe we should keep regex?
                    # But generally we trust the AI context window.
                    
                    return {
                        "status": report.get("status", "UNKNOWN"),
                        "findings": llm_findings, # ONLY return AI-verified findings
                        "plan": plan,
                        "ai_malicious_risk": ai_scan
                    }
                else:
                    return {
                        "status": "SAFE",
                        "plan": plan,
                        "findings": [], # If Phase 1 says SAFE, discard regex noise
                        "ai_malicious_risk": ai_scan,
                        "reason": "Phase 1 analysis determined code is safe."
                    }

            return {"status": "ERROR", "error": f"Unknown mode: {mode}"}
            
        except Exception as e:
            self.logger.error(f"Pipeline crashed: {e}")
            import traceback
            self.logger.debug(traceback.format_exc())
            return {
                "status": "ERROR",
                "error": f"Scan failed: {str(e)}",
                "findings": []
            }

    def _run_phase1(self, code: str, structure: Dict, categories: List[str], semantic_findings: List[Dict]) -> Dict:
        """Execute Phase 1: Planning"""
        summary = f"""
        Categories Found: {', '.join(categories)}
        Functions: {len(structure.get('functions', []))}
        Imports: {len(structure.get('imports', []))}
        Potential Semantic Issues: {len(semantic_findings)}
        """
        
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
        """Execute Phase 2: Deep Analysis (Memory-optimized)"""
        critical_funcs = plan.get("critical_functions", [])
        focus_areas = plan.get("focus_areas", [])
        
        # Truncate code to prevent OOM on free tier (max 15KB)
        max_code_len = 15000
        truncated_code = code[:max_code_len]
        if len(code) > max_code_len:
            truncated_code += f"\n\n... [TRUNCATED - {len(code) - max_code_len} bytes omitted]"
        
        # Limit semantic findings to prevent bloat
        limited_findings = semantic_findings[:20] if len(semantic_findings) > 20 else semantic_findings
        
        context = f"""
        PHASE 1 PLAN:
        Risk Level: {plan.get('risk_level')}
        Focus Areas: {json.dumps(focus_areas[:10])}
        
        SEMANTIC HINTS ({len(limited_findings)} of {len(semantic_findings)}):
        {json.dumps(limited_findings)}
        
        CODE (truncated to {len(truncated_code)} chars):
        {truncated_code}
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
            return {"status": "ERROR", "error": str(e), "findings": []}

    def _parse_json_response(self, response: str) -> Dict:
        """Extract and parse JSON from LLM response"""
        parsed = None
        try:
            # Try standard json first
            import json_repair
            parsed = json_repair.loads(response)
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
                    
                parsed = json.loads(json_str)
            except Exception as e:
                self.logger.error(f"JSON Parsing failed: {e}")
                return {"raw_response": response, "error": "Failed to parse JSON"}
        
        # Enforce Dict return type
        if isinstance(parsed, dict):
            return parsed
        elif isinstance(parsed, list):
            return {"data": parsed}
        else:
            # String or other primitive
            return {"parsed_content": str(parsed), "raw_response": response}
