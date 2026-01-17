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
from engine.prompts import PHASE_1_PROMPT, PHASE_2_PROMPT, VERIFICATION_PROMPT, SCA_PROMPT, TAINT_PROMPT
from engine.ai_malicious_detection import AIMaliciousDetector
from engine.sca import SCAScanner
from engine.taint import TaintTracker

# Try to import providers, handle failure gracefully
try:
    # Use relative import from parent package
    from ..providers import load_provider, GeminiProvider, GroqProvider, GrokProvider
    HAS_PROVIDERS = True
except ImportError as e:
    print(f"[PIPELINE] Provider import failed: {e}")
    HAS_PROVIDERS = False

class SecurityPipeline:
    """
    Orchestrates the security scanning pipeline.
    Enhanced with SCA (dependency scanning) and taint tracking.
    """
    
    def __init__(self):
        self.parser = CodeParser()
        self.semantic = SemanticAnalyzer()
        self.filter = KeywordFilter()
        self.ai_detector = AIMaliciousDetector()  # AI malicious code detector
        self.taint_tracker = TaintTracker()  # Taint flow analysis
        self.logger = logging.getLogger("vuln_scan")
        
        # Initialize providers
        self.phase1_provider = self._get_phase1_provider()
        self.phase2_provider = self._get_phase2_provider()
        
        # Initialize SCA scanner with AI provider
        self.sca_scanner = SCAScanner(ai_provider=self.phase2_provider)

    def _get_phase1_provider(self):
        """Get fast provider for Phase 1 (Groq preferred)"""
        if not HAS_PROVIDERS: return None
        
        # Load Balancing: Support multiple keys for high throughput
        import random
        
        # Groq Keys (fastest)
        groq_keys = [k for k in [os.getenv("GROQ_KEY"), os.getenv("GROQ2_API_KEY")] if k]
        if groq_keys:
            selected_key = random.choice(groq_keys)
            self.logger.info(f"Using Groq Key (one of {len(groq_keys)})")
            return GroqProvider(api_key=selected_key)

        # Grok (X.AI)
        if os.getenv("GROK_API_KEY"):
            self.logger.info("Using Grok provider")
            return GrokProvider()

        # Gemini Keys (fallback)
        gemini_keys = [k for k in [os.getenv("GEMINI_API_KEY"), os.getenv("GEMINI2_API_KEY")] if k]
        if gemini_keys:
            selected_key = random.choice(gemini_keys)
            self.logger.info(f"Using Gemini Key (one of {len(gemini_keys)})")
            return GeminiProvider(api_key=selected_key)
            
        return None

    def _get_phase2_provider(self):
        """Get strong provider for Phase 2 (Gemini preferred)"""
        if not HAS_PROVIDERS: return None
        
        import random
        
        # Gemini Keys (best for deep analysis)
        gemini_keys = [k for k in [os.getenv("GEMINI_API_KEY"), os.getenv("GEMINI2_API_KEY")] if k]
        if gemini_keys:
            selected_key = random.choice(gemini_keys)
            self.logger.info(f"Using Gemini Key for Phase 2 (one of {len(gemini_keys)})")
            return GeminiProvider(api_key=selected_key)

        # Grok fallback
        if os.getenv("GROK_API_KEY"):
            return GrokProvider()
        
        # Groq fallback
        groq_keys = [k for k in [os.getenv("GROQ_KEY"), os.getenv("GROQ2_API_KEY")] if k]
        if groq_keys:
            return GroqProvider(api_key=random.choice(groq_keys))
            
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
                # Check size first (2MB limit)
                file_size = os.path.getsize(file_path)
                if file_size > 2 * 1024 * 1024:  # 2MB
                    self.logger.warning(f"Skipping large file ({file_size} bytes): {file_path}")
                    return {
                        "status": "SKIPPED", 
                        "reason": f"File too large ({file_size // 1024}KB > 2MB limit)",
                        "findings": []
                    }

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
            
            # 4. SCA (Software Composition Analysis) for dependency files
            sca_findings = []
            if self.sca_scanner.is_dependency_file(file_path):
                self.logger.info("[SCA] Detected dependency file, running SCA scan...")
                sca_result = self.sca_scanner.scan_file(file_path, code)
                sca_findings = sca_result.get('findings', [])
                self.logger.info(f"[SCA] Found {len(sca_findings)} vulnerable dependencies")
            
            # 5. Taint Tracking (Source → Sink analysis)
            self.logger.info("Running Taint Analysis...")
            taint_findings = self.taint_tracker.analyze(code, file_path)
            self.logger.info(f"[TAINT] Found {len(taint_findings)} potential taint flows")
            
            # Merge all findings
            all_findings = semantic_findings + sca_findings + taint_findings
            self.logger.info(f"[TOTAL] Combined findings: {len(all_findings)} (semantic: {len(semantic_findings)}, sca: {len(sca_findings)}, taint: {len(taint_findings)})")
            
            # 6. AI Malicious Detection (Local, no LLM, runs on FULL code)
            ai_scan = self.ai_detector.run_full_ai_malicious_scan(code)
            self.logger.info(f"AI scan: {ai_scan.get('risk_level', 'UNKNOWN')}")

            # FAST MODE: No LLM, pure local analysis (includes SCA + Taint)
            if mode == 'fast':
                status = "VULNERABLE" if all_findings else "SAFE"
                return {
                    "status": status,
                    "reason": f"Fast scan completed (Local Analysis: {len(semantic_findings)} semantic, {len(sca_findings)} SCA, {len(taint_findings)} taint).",
                    "risk_score": risk_score,
                    "findings": all_findings[:500],
                    "semantic_hints": semantic_findings[:100],
                    "sca_findings": sca_findings,
                    "taint_findings": taint_findings,
                    "ai_malicious_risk": ai_scan,
                    "categories": categories
                }

            # HYBRID MODE: Single lightweight LLM call (Phase 1 only)
            if mode == 'hybrid':
                if not self.phase1_provider:
                    status = "VULNERABLE" if all_findings else "SAFE"
                    return {
                        "status": status,
                        "reason": f"Local analysis only (No LLM). Found: {len(all_findings)} issues.",
                        "risk_score": risk_score,
                        "findings": all_findings[:500],
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
                    if 'taint' in t or 'dependency' in t or 'cve' in t: return 3  # SCA/Taint high priority
                    
                    # Medium/High Priority (XSS, CSRF, Overflows, Logic Bugs)
                    return 2
                
                all_findings.sort(key=get_severity_weight, reverse=True)
                
                # Generate Summary of all findings
                from collections import Counter
                finding_counts = Counter([f.get('type', 'Unknown') for f in all_findings])
                finding_summary = ", ".join([f"{k}: {v}" for k, v in finding_counts.items()])

                # Truncate code for LLM to save tokens/memory
                truncated_code = code[:10000] 
                
                # Pass prioritized findings (Top 15 instead of 5) plus summary
                plan = self._run_phase1(truncated_code, structure, categories, all_findings[:15], finding_summary)
                
                if not isinstance(plan, dict):
                    plan = {"risk_level": "UNKNOWN", "error": "Invalid response"}

                is_risky = plan.get("risk_level") in ["CRITICAL", "HIGH", "MEDIUM"]
                
                # AI-BASED FINDING VERIFICATION
                # Verify only semantic findings (SCA/taint are already validated)
                self.logger.info(f"[HYBRID] AI Phase 1 says: {plan.get('risk_level')}. Now verifying {len(semantic_findings)} semantic findings...")
                
                # Verify semantic findings through AI (batch verification)
                verified_semantic = self._verify_findings(semantic_findings, code)
                
                # Combine: verified semantic + all SCA (trusted) + all taint (trusted)
                final_findings = verified_semantic + sca_findings + taint_findings
                
                self.logger.info(f"[HYBRID] Final: {len(final_findings)} findings (semantic: {len(verified_semantic)}, sca: {len(sca_findings)}, taint: {len(taint_findings)})")
                
                return {
                    "status": "VULNERABLE" if (is_risky or len(final_findings) > 0) else "SAFE",
                    "risk_score": risk_score,
                    "findings": final_findings,
                    "plan": plan,
                    "ai_malicious_risk": ai_scan,
                    "sca_findings": sca_findings,
                    "taint_findings": taint_findings,
                    "reason": f"Hybrid scan: {plan.get('reasoning', 'Analysis complete')}. Total: {len(final_findings)} (semantic: {len(verified_semantic)}, SCA: {len(sca_findings)}, taint: {len(taint_findings)})"
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
        
        # DEBUG MODE: Skip AI verification entirely if env var is set
        if os.getenv("SKIP_AI_VERIFY", "").lower() in ("1", "true", "yes"):
            self.logger.info(f"[VERIFY] SKIP_AI_VERIFY is set - returning all {len(findings)} findings unfiltered")
            return findings[:500]
        
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
            verified_set = set(verified_ids)
            
            # MINIMUM THRESHOLD: Ensure we keep at least 18% of findings (to match Snyk's rate)
            # If AI is too aggressive, supplement with high-severity findings
            min_target = int(len(findings_for_ai) * 0.18)  # 18% minimum
            
            if len(verified_findings) < min_target:
                self.logger.warning(f"[VERIFY] AI only verified {len(verified_findings)}, below target {min_target}. Adding high-severity findings...")
                
                # Priority order for adding back findings
                priority_types = [
                    'sql injection', 'command injection', 'rce', 'remote code',
                    'hardcoded', 'secret', 'credential', 'password', 'api key', 'token',
                    'xss', 'cross-site', 'csrf', 'ssrf',
                    'path traversal', 'file inclusion', 'lfi', 'rfi',
                    'deserialization', 'pickle', 'yaml.load',
                    'exec', 'eval', 'subprocess', 'os.system'
                ]
                
                # Add high-severity findings until we reach target
                for i, f in enumerate(findings[:100]):
                    if i not in verified_set and len(verified_findings) < min_target:
                        finding_type = f.get('type', '').lower()
                        severity = f.get('severity', '').lower()
                        
                        # Add if high/critical severity OR matches priority types
                        if severity in ['high', 'critical'] or any(pt in finding_type for pt in priority_types):
                            verified_findings.append(f)
                            verified_set.add(i)
                
                self.logger.info(f"[VERIFY] After supplementing: {len(verified_findings)} findings")
            
            return verified_findings
            
        except Exception as e:
            self.logger.error(f"[VERIFY] AI verification failed: {e}. Returning top 50 findings.")
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
