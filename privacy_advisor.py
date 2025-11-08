"""
AI Privacy Advisor module for providing actionable privacy recommendations.
Supports both rule-based and AI-powered (Grok API) recommendations.
"""

import os
import requests
import json
from typing import Dict, List, Optional
from utils.display import print_warning, print_info


class PrivacyAdvisor:
    """Provides AI-powered privacy recommendations based on scan results."""
    
    def __init__(self, grok_api_key: Optional[str] = None):
        """
        Initialize the privacy advisor.
        
        Args:
            grok_api_key: Optional Grok API key for AI-powered recommendations
        """
        self.grok_api_key = grok_api_key
        self.grok_api_url = "https://api.x.ai/v1/chat/completions"
        self.use_ai = grok_api_key and grok_api_key != "YOUR_GROK_API_KEY_HERE"
    
    def get_rule_based_recommendations(self,
                                      breakdown: Dict,
                                      search_results: Dict[str, List[Dict]],
                                      breach_data: Dict) -> List[str]:
        """
        Generate rule-based privacy recommendations.
        
        Args:
            breakdown: Detailed risk breakdown dictionary
            search_results: Search results dictionary
            breach_data: Breach data dictionary
        
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        # Extract data from breakdown
        public_exposure = breakdown.get('public_exposure', {})
        sensitive_exposure = breakdown.get('sensitive_exposure', {})
        is_famous = breakdown.get('is_famous', False)
        
        public_score = public_exposure.get('score', 0)
        sensitive_score = sensitive_exposure.get('score', 0)
        
        public_breakdown = public_exposure.get('breakdown', {})
        sensitive_breakdown = sensitive_exposure.get('breakdown', {})
        
        # Public Exposure recommendations
        name_mentions = public_breakdown.get('name_mentions_count', 0)
        if name_mentions > 0 and not is_famous:
            if name_mentions > 15:
                recommendations.append("🚨 High public exposure detected. Consider removing personal information from public profiles.")
                recommendations.append("💡 Review and tighten privacy settings on all social media platforms.")
            elif name_mentions > 5:
                recommendations.append("⚠️  Moderate public exposure. Limit personal information shared online.")
                recommendations.append("💡 Consider using a pseudonym for online activities.")
            else:
                recommendations.append("💡 Low public exposure. Maintain current privacy practices.")
        
        if is_famous:
            recommendations.append("ℹ️  Public figure detected. Public mentions are expected, but protect sensitive information.")
        
        # Sensitive Exposure recommendations
        email_mentions = sensitive_breakdown.get('email_mentions_count', 0)
        if email_mentions > 0:
            recommendations.append("🚨 Email address found in public searches. This is a serious privacy risk.")
            recommendations.append("🔐 Immediately remove email from public profiles and websites.")
            recommendations.append("📧 Use email aliases for future online registrations.")
        
        username_mentions = sensitive_breakdown.get('username_mentions_count', 0)
        if username_mentions > 5:
            recommendations.append("⚠️  Username found in multiple places. Consider changing usernames on old accounts.")
            recommendations.append("💡 Use unique usernames for different platforms to prevent tracking.")
        
        # Breach recommendations
        breaches_count = sensitive_breakdown.get('breaches_count', 0)
        if breaches_count > 0:
            recommendations.append(f"🚨 Found {breaches_count} data breach(es). This is critical.")
            recommendations.append("🔐 Change passwords for ALL breached services immediately.")
            recommendations.append("🔐 Use unique, strong passwords for each account.")
            recommendations.append("🔐 Enable two-factor authentication (2FA) wherever possible.")
            recommendations.append("🔐 Consider using a password manager (e.g., Bitwarden, 1Password).")
        
        pastes_count = sensitive_breakdown.get('pastes_count', 0)
        if pastes_count > 0:
            recommendations.append(f"⚠️  Email found in {pastes_count} paste(s). Monitor for identity theft.")
            recommendations.append("🔐 Change passwords and enable 2FA on all accounts using this email.")
        
        # Overall risk level recommendations
        total_score = breakdown.get('total_score', 0)
        if total_score > 70:
            recommendations.append("🚨 CRITICAL: Your privacy exposure is very high. Take immediate action.")
            recommendations.append("💡 Consider professional identity protection services.")
        elif total_score > 40:
            recommendations.append("⚠️  Your privacy exposure is moderate. Take proactive steps to reduce it.")
        else:
            recommendations.append("✅ Your privacy exposure is relatively low. Maintain good privacy habits.")
        
        # General best practices
        if sensitive_score > 20:
            recommendations.append("💡 Use a VPN when browsing to protect your online activity.")
            recommendations.append("💡 Regularly review and delete old online accounts.")
            recommendations.append("💡 Be cautious about sharing personal information online.")
        
        return recommendations
    
    def get_ai_recommendations(self,
                              breakdown: Dict,
                              search_results: Dict[str, List[Dict]],
                              breach_data: Dict) -> Optional[List[str]]:
        """
        Get AI-powered recommendations using Grok API.
        
        Args:
            breakdown: Detailed risk breakdown dictionary
            search_results: Search results dictionary
            breach_data: Breach data dictionary
        
        Returns:
            List of recommendation strings, or None if API call fails
        """
        if not self.use_ai:
            return None
        
        try:
            # Prepare summary of findings
            public_score = breakdown.get('public_exposure', {}).get('score', 0)
            sensitive_score = breakdown.get('sensitive_exposure', {}).get('score', 0)
            total_score = breakdown.get('total_score', 0)
            
            name_mentions = len(search_results.get('name', []))
            email_mentions = len(search_results.get('email', []))
            username_mentions = len(search_results.get('username', []))
            breaches = breach_data.get('total_breaches', 0)
            pastes = len(breach_data.get('pastes', []))
            
            prompt = f"""Given these online exposure results, summarize the risk and provide 3-5 actionable privacy improvements.

Risk Assessment:
- Total Risk Score: {total_score}/100
- Public Exposure: {public_score}/50 (Name mentions: {name_mentions})
- Sensitive Exposure: {sensitive_score}/50
- Email mentions: {email_mentions}
- Username mentions: {username_mentions}
- Data breaches: {breaches}
- Pastes found: {pastes}

Provide a concise summary of the risk level and 3-5 specific, actionable recommendations to reduce privacy exposure. Format as a numbered list."""
            
            headers = {
                'Authorization': f'Bearer {self.grok_api_key}',
                'Content-Type': 'application/json'
            }
            
            data = {
                'model': 'grok-beta',
                'messages': [
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
                'temperature': 0.7,
                'max_tokens': 500
            }
            
            print_info("🤖 Generating AI-powered privacy recommendations...")
            response = requests.post(self.grok_api_url, headers=headers, json=data, timeout=15)
            response.raise_for_status()
            
            result = response.json()
            content = result.get('choices', [{}])[0].get('message', {}).get('content', '')
            
            # Parse AI response into recommendations list
            recommendations = []
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if line and (line[0].isdigit() or line.startswith('-') or line.startswith('•')):
                    # Clean up formatting
                    line = line.lstrip('0123456789.-•) ').strip()
                    if line:
                        recommendations.append(f"🤖 {line}")
            
            if not recommendations:
                # Fallback: use the whole response
                recommendations = [f"🤖 {content}"]
            
            return recommendations[:5]  # Limit to 5 recommendations
        
        except requests.exceptions.RequestException as e:
            print_warning(f"⚠️  Could not fetch AI recommendations: {str(e)}")
            return None
        except Exception as e:
            print_warning(f"⚠️  Error with AI recommendations: {str(e)}")
            return None
    
    def get_recommendations(self,
                           breakdown: Dict,
                           search_results: Dict[str, List[Dict]],
                           breach_data: Dict) -> List[str]:
        """
        Get privacy recommendations (AI-powered if available, otherwise rule-based).
        
        Args:
            breakdown: Detailed risk breakdown dictionary
            search_results: Search results dictionary
            breach_data: Breach data dictionary
        
        Returns:
            List of recommendation strings
        """
        # Try AI recommendations first if available
        if self.use_ai:
            ai_recommendations = self.get_ai_recommendations(breakdown, search_results, breach_data)
            if ai_recommendations:
                return ai_recommendations
        
        # Fall back to rule-based recommendations
        return self.get_rule_based_recommendations(breakdown, search_results, breach_data)

