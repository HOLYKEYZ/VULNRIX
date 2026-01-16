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
from engine.prompts import PHASE_1_PROMPT, PHASE_2_PROMPT, VERIFICATION_PROMPT
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
        
        # Load Balancing: Support multiple keys for high throughput
        import random
        
        # Groq Keys
        groq_keys = [k for k in [os.getenv("GROQ_KEY"), os.getenv("GROQ2_API_KEY")] if k]
        if groq_keys:
            selected_key = random.choice(groq_keys)
            self.logger.info(f"Using Groq Key (one of {len(groq_keys)})")
            return GroqProvider(api_key=selected_key)

        # OpenAI
        if os.getenv("OPENAI_API_KEY"):
            return OpenAIProvider(model="gpt-3.5-turbo")

        # Gemini Keys
        gemini_keys = [k for k in [os.getenv("GEMINI_API_KEY"), os.getenv("GEMINI2_API_KEY")] if k]
        if gemini_keys:
            selected_key = random.choice(gemini_keys)
            self.logger.info(f"Using Gemini Key (one of {len(gemini_keys)})")
            return GeminiProvider(api_key=selected_key, model="gemini-1.5-flash")
            
        return None

    def _get_phase2_provider(self):
        """Get strong provider for Phase 2 (Gemini/Claude/GPT-4)"""
        if not HAS_PROVIDERS: return None
        
        import random
        
        # Gemini Keys (Pro model)
        gemini_keys = [k for k in [os.getenv("GEMINI_API_KEY"), os.getenv("GEMINI2_API_KEY")] if k]
        if gemini_keys:
            selected_key = random.choice(gemini_keys)
            self.logger.info(f"Using Gemini Key for Phase 2 (one of {len(gemini_keys)})")
            return GeminiProvider(api_key=selected_key, model="gemini-1.5-pro")

        if os.getenv("ANTHROPIC_API_KEY"):
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
                
                # INTELLIGENT HINT SELECTION
                # Sort findings to prioritize High Severity ones for the LLM Context
                def get_severity_weight(f):
                    t = f.get('type', '').lower()
                    # Critical/High Priority
                    if 'credential' in t or 'secret' in t or 'key' in t: return 3
                    if 'sql' in t or 'command' in t or 'remote' in t or 'exec' in t: return 3
                    
                    # Medium/High Priority (XSS, CSRF, Overflows, Logic Bugs)
                    # DEFAULT TO 2 for almost everything to ensure we don't drop valid regex hits.
                    return 2
                
                semantic_findings.sort(key=get_severity_weight, reverse=True)
                
                # Generate Summary of all findings
                from collections import Counter
                finding_counts = Counter([f.get('type', 'Unknown') for f in semantic_findings])
                finding_summary = ", ".join([f"{k}: {v}" for k, v in finding_counts.items()])

                # Truncate code for LLM to save tokens/memory
                truncated_code = code[:10000] 
                
                # Pass prioritized findings (Top 15 instead of 5) plus summary
                plan = self._run_phase1(truncated_code, structure, categories, semantic_findings[:15], finding_summary)
                
                if not isinstance(plan, dict):
                    plan = {"risk_level": "UNKNOWN", "error": "Invalid response"}

                is_risky = plan.get("risk_level") in ["CRITICAL", "HIGH", "MEDIUM"]
                
                # NEW: AI-BASED FINDING VERIFICATION
                # Instead of blindly trusting all regex hits, verify them through AI.
                # This dramatically reduces false positives (275 -> ~50).
                self.logger.info(f"[HYBRID] AI Phase 1 says: {plan.get('risk_level')}. Now verifying {len(semantic_findings)} regex findings...")
                
                # Verify findings through AI (batch verification)
                verified_findings = self._verify_findings(semantic_findings, code)
                
                self.logger.info(f"[HYBRID] AI verified {len(verified_findings)}/{len(semantic_findings)} findings as true positives.")
                
                return {
                    "status": "VULNERABLE" if (is_risky or len(verified_findings) > 0) else "SAFE",
                    "risk_score": risk_score,
                    "findings": verified_findings,
                    "plan": plan,
                    "ai_malicious_risk": ai_scan,
                    "reason": f"Hybrid scan: {plan.get('reasoning', 'Analysis complete')}. Verified {len(verified_findings)} of {len(semantic_findings)} regex findings."
                }


            # Deep mode is deprecated - redirect to hybrid
            if mode == 'deep':
                self.logger.warning("Deep mode deprecated, using hybrid instead.")
                mode = 'hybrid'
                # Re-run hybrid logic (code already handled above)
                return self.scan_file(file_path, mode='hybrid')

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

    def _run_phase1(self, code: str, structure: Dict, categories: List[str], semantic_findings: List[Dict], finding_summary: str = "") -> Dict:
        """Execute Phase 1: Planning"""
        summary = f"""
        Categories Found: {', '.join(categories)}
        Functions: {len(structure.get('functions', []))}
        Imports: {len(structure.get('imports', []))}
        Potential Semantic Issues (Total): {len(semantic_findings)} (Summary: {finding_summary})
        """
        
        context = f"METADATA:\n{summary}\n\nTOP RISK HINTS:\n{json.dumps(semantic_findings)}\n\nCODE SUMMARY:\n{code[:8000]}" 
        
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

    def _verify_findings(self, findings: List[Dict], code: str = "") -> List[Dict]:
        """
        Batch verify regex findings using AI to filter false positives.
        Sends all findings to AI and returns only the verified ones.
        """
        if not findings:
            return []
        
        # If no AI provider, skip verification (return all)
        if not self.phase1_provider:
            self.logger.warning("[VERIFY] No AI provider configured, skipping verification")
            return findings
        
        # Prepare findings for AI (add IDs, limit context)
        findings_for_ai = []
        for i, f in enumerate(findings[:100]):  # Limit to 100 to avoid token overflow
            findings_for_ai.append({
                "id": i,
                "type": f.get("type", "Unknown"),
                "severity": f.get("severity", "Medium"),
                "description": f.get("description", "")[:200],  # Truncate
                "code": f.get("matched_content", f.get("code", ""))[:150],  # Truncate
                "location": f.get("location", {})
            })
        
        # Build context
        context = json.dumps(findings_for_ai, indent=2)
        if code:
            # Add a code snippet for context (first 5000 chars)
            context += f"\n\n--- CODE CONTEXT (first 5000 chars) ---\n{code[:5000]}"
        
        try:
            self.logger.info(f"[VERIFY] Sending {len(findings_for_ai)} findings to AI for verification...")
            response = self.phase1_provider.ask(
                system_prompt=VERIFICATION_PROMPT,
                user_prompt="Verify these findings. Return only valid vulnerability IDs.",
                context=context
            )
            
            result = self._parse_json_response(response)
            verified_ids = result.get("verified_ids", [])
            reasoning = result.get("reasoning", "No explanation provided")
            
            self.logger.info(f"[VERIFY] AI verified {len(verified_ids)}/{len(findings_for_ai)} findings. Reason: {reasoning[:100]}")
            
            # Return only verified findings
            verified_findings = [f for i, f in enumerate(findings[:100]) if i in verified_ids]
            
            # If AI verified nothing but we had many findings, something might be wrong
            # As a safety net, if AI rejected >90%, at least keep critical ones
            if len(verified_ids) == 0 and len(findings) > 10:
                self.logger.warning("[VERIFY] AI rejected all findings! Keeping critical secrets/injection as fallback.")
                critical_types = ['hardcoded', 'secret', 'credential', 'sql injection', 'command injection', 'rce']
                verified_findings = [f for f in findings[:100] if any(ct in f.get('type', '').lower() for ct in critical_types)]
            
            return verified_findings
            
        except Exception as e:
            self.logger.error(f"[VERIFY] AI verification failed: {e}. Returning unfiltered findings.")
            # On failure, return top 50 findings to avoid spam
            return findings[:50]


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
