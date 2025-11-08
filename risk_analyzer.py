"""
Risk analysis module for calculating exposure risk scores.
Separates Public Exposure and Sensitive Exposure with fame adjustment.
"""

from typing import Dict, List, Optional, Tuple


class RiskAnalyzer:
    """Calculates risk scores based on search results and breach data."""
    
    def __init__(self):
        """Initialize the risk analyzer."""
        self.base_score = 0
    
    def detect_fame(self, name: Optional[str], search_results: Dict[str, List[Dict]]) -> bool:
        """
        Detect if the person is likely a public figure based on search results.
        
        Args:
            name: Name to check
            search_results: Search results dictionary
        
        Returns:
            True if likely a public figure, False otherwise
        """
        if not name:
            return False
        
        name_results = search_results.get('name', [])
        
        # Heuristics for fame detection:
        # 1. High number of name mentions (>20)
        # 2. Results mention "Wikipedia", "celebrity", "famous", "actor", "politician", etc.
        if len(name_results) > 20:
            # Check for public figure indicators in results
            fame_indicators = [
                'wikipedia', 'celebrity', 'famous', 'actor', 'actress',
                'politician', 'athlete', 'singer', 'musician', 'author',
                'director', 'producer', 'news', 'biography', 'official'
            ]
            
            for result in name_results[:10]:  # Check first 10 results
                title = result.get('title', '').lower()
                snippet = result.get('snippet', '').lower()
                combined = title + ' ' + snippet
                
                if any(indicator in combined for indicator in fame_indicators):
                    return True
        
        return False
    
    def calculate_public_exposure(self, 
                                 search_results: Dict[str, List[Dict]],
                                 has_name: bool = False,
                                 is_famous: bool = False) -> Tuple[int, Dict]:
        """
        Calculate Public Exposure score (0-50) based on name mentions.
        
        Args:
            search_results: Dictionary with search results
            has_name: Whether a name was provided
            is_famous: Whether the person is a public figure
        
        Returns:
            Tuple of (score, breakdown_dict)
        """
        score = 0
        breakdown = {
            'name_mentions': 0,
            'name_mentions_count': 0,
            'fame_adjustment': 0,
            'fame_detected': is_famous
        }
        
        name_results = search_results.get('name', [])
        breakdown['name_mentions_count'] = len(name_results)
        
        if has_name:
            # Base scoring for name mentions (0-30 points)
            if len(name_results) == 0:
                score += 0
            elif len(name_results) <= 3:
                score += 10
            elif len(name_results) <= 7:
                score += 15
            elif len(name_results) <= 15:
                score += 20
            else:
                score += 30
            
            breakdown['name_mentions'] = score
            
            # Fame adjustment: reduce weight for public figures
            if is_famous:
                # Reduce public exposure score by 50% for famous people
                # (their public presence is expected)
                adjustment = int(score * 0.5)
                score = score - adjustment
                breakdown['fame_adjustment'] = adjustment
                breakdown['fame_detected'] = True
        
        # Cap at 50 points
        return min(50, max(0, score)), breakdown
    
    def calculate_sensitive_exposure(self,
                                     search_results: Dict[str, List[Dict]],
                                     breach_data: Dict,
                                     has_email: bool = False,
                                     has_username: bool = False) -> Tuple[int, Dict]:
        """
        Calculate Sensitive Exposure score (0-50) based on email, username, and breaches.
        
        Args:
            search_results: Dictionary with search results
            breach_data: Dictionary with breach information
            has_email: Whether an email was provided
            has_username: Whether a username was provided
        
        Returns:
            Tuple of (score, breakdown_dict)
        """
        score = 0
        breakdown = {
            'email_mentions': 0,
            'email_mentions_count': 0,
            'username_mentions': 0,
            'username_mentions_count': 0,
            'breaches': 0,
            'breaches_count': 0,
            'pastes': 0,
            'pastes_count': 0
        }
        
        # Email mentions (0-15 points)
        email_results = search_results.get('email', [])
        breakdown['email_mentions_count'] = len(email_results)
        
        if has_email:
            if len(email_results) == 0:
                score += 0
            elif len(email_results) <= 2:
                score += 10  # Email exposure is serious
            elif len(email_results) <= 5:
                score += 13
            else:
                score += 15
            breakdown['email_mentions'] = score
        
        # Username mentions (0-10 points)
        username_results = search_results.get('username', [])
        breakdown['username_mentions_count'] = len(username_results)
        
        if has_username:
            if len(username_results) == 0:
                score += 0
            elif len(username_results) <= 3:
                score += 5
            elif len(username_results) <= 7:
                score += 8
            else:
                score += 10
            breakdown['username_mentions'] = score - breakdown['email_mentions']
        
        # Breach data scoring (0-20 points)
        total_breaches = breach_data.get('total_breaches', 0)
        pastes_count = len(breach_data.get('pastes', []))
        
        breakdown['breaches_count'] = total_breaches
        breakdown['pastes_count'] = pastes_count
        
        # Breach scoring (0-15 points)
        if total_breaches == 0:
            score += 0
        elif total_breaches == 1:
            score += 8
        elif total_breaches <= 3:
            score += 12
        else:
            score += 15
        breakdown['breaches'] = score - breakdown['email_mentions'] - breakdown['username_mentions']
        
        # Paste scoring (0-5 points)
        if pastes_count == 0:
            score += 0
        elif pastes_count == 1:
            score += 3
        else:
            score += 5
        breakdown['pastes'] = score - (breakdown['email_mentions'] + 
                                      breakdown['username_mentions'] + 
                                      breakdown['breaches'])
        
        # Cap at 50 points
        return min(50, max(0, score)), breakdown
    
    def calculate_risk_score(self, 
                           search_results: Dict[str, List[Dict]], 
                           breach_data: Dict,
                           has_name: bool = False,
                           has_email: bool = False,
                           has_username: bool = False,
                           name: Optional[str] = None) -> Tuple[int, Dict]:
        """
        Calculate total risk score from 0-100 based on findings.
        Separates Public Exposure and Sensitive Exposure.
        
        Args:
            search_results: Dictionary with 'name', 'email', 'username' keys containing search results
            breach_data: Dictionary with breach information
            has_name: Whether a name was provided
            has_email: Whether an email was provided
            has_username: Whether a username was provided
            name: Name string for fame detection
        
        Returns:
            Tuple of (total_score, detailed_breakdown_dict)
        """
        # Detect if person is a public figure
        is_famous = self.detect_fame(name, search_results)
        
        # Calculate Public Exposure (0-50)
        public_score, public_breakdown = self.calculate_public_exposure(
            search_results, has_name, is_famous
        )
        
        # Calculate Sensitive Exposure (0-50)
        sensitive_score, sensitive_breakdown = self.calculate_sensitive_exposure(
            search_results, breach_data, has_email, has_username
        )
        
        # Total score is sum of both (0-100)
        total_score = public_score + sensitive_score
        
        # Compile detailed breakdown
        breakdown = {
            'total_score': total_score,
            'public_exposure': {
                'score': public_score,
                'breakdown': public_breakdown
            },
            'sensitive_exposure': {
                'score': sensitive_score,
                'breakdown': sensitive_breakdown
            },
            'is_famous': is_famous
        }
        
        return total_score, breakdown
    
    def get_risk_level(self, score: int) -> str:
        """
        Get risk level category based on score.
        
        Args:
            score: Risk score from 0-100
        
        Returns:
            Risk level: 'safe', 'warning', or 'danger'
        """
        if score <= 30:
            return 'safe'
        elif score <= 70:
            return 'warning'
        else:
            return 'danger'
    
    def get_recommendations(self, 
                          score: int,
                          search_results: Dict[str, List[Dict]],
                          breach_data: Dict) -> List[str]:
        """
        Generate basic recommendations based on findings.
        (More advanced AI recommendations are in privacy_advisor.py)
        
        Args:
            score: Risk score
            search_results: Search results dictionary
            breach_data: Breach data dictionary
        
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        if score <= 30:
            recommendations.append("✅ Your digital footprint appears relatively safe.")
            recommendations.append("💡 Continue practicing good privacy habits.")
        elif score <= 70:
            recommendations.append("⚠️  Your information has moderate exposure online.")
            recommendations.append("💡 Consider removing personal information from public profiles.")
            recommendations.append("💡 Review your social media privacy settings.")
        else:
            recommendations.append("🚨 Your information has significant exposure online.")
            recommendations.append("💡 Immediately change passwords for any breached accounts.")
            recommendations.append("💡 Enable two-factor authentication where possible.")
            recommendations.append("💡 Consider using a password manager.")
            recommendations.append("💡 Review and remove unnecessary online profiles.")
        
        # Specific recommendations based on findings
        if breach_data.get('total_breaches', 0) > 0:
            recommendations.append("🔐 Change passwords for breached services immediately.")
        
        if len(search_results.get('email', [])) > 0:
            recommendations.append("📧 Consider using email aliases for online registrations.")
        
        if len(search_results.get('name', [])) > 5:
            recommendations.append("👤 Consider using a pseudonym for online activities.")
        
        return recommendations
