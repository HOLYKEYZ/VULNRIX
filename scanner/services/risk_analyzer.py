"""
Risk analysis module for calculating exposure risk scores.
"""
from typing import Dict, List, Optional, Tuple


class RiskAnalyzer:
    """Calculates risk scores based on scan results."""
    
    def __init__(self):
        """Initialize the risk analyzer."""
        pass
    
    def detect_fame(self, name: Optional[str], search_results: Dict[str, List[Dict]]) -> bool:
        """Detect if the person is likely a public figure."""
        if not name:
            return False
        
        name_results = search_results.get('name', [])
        
        if len(name_results) > 20:
            fame_indicators = [
                'wikipedia', 'celebrity', 'famous', 'actor', 'actress',
                'politician', 'athlete', 'singer', 'musician', 'author',
                'director', 'producer', 'news', 'biography', 'official'
            ]
            
            for result in name_results[:10]:
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
        """Calculate Public Exposure score (0-50)."""
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
            
            if is_famous:
                adjustment = int(score * 0.5)
                score = score - adjustment
                breakdown['fame_adjustment'] = adjustment
                breakdown['fame_detected'] = True
        
        return min(50, max(0, score)), breakdown
    
    def calculate_sensitive_exposure(self,
                                     search_results: Dict[str, List[Dict]],
                                     breach_data: Dict,
                                     has_email: bool = False,
                                     has_username: bool = False) -> Tuple[int, Dict]:
        """Calculate Sensitive Exposure score (0-50)."""
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
                score += 10
            elif len(email_results) <= 5:
                score += 13
            else:
                score += 15
            breakdown['email_mentions'] = score
        
        # Username mentions (0-10 points)
        username_results = search_results.get('username', [])
        breakdown['username_mentions_count'] = len(username_results)
        
        if has_username:
            username_score = 0
            if len(username_results) == 0:
                username_score = 0
            elif len(username_results) <= 3:
                username_score = 5
            elif len(username_results) <= 7:
                username_score = 8
            else:
                username_score = 10
            score += username_score
            breakdown['username_mentions'] = username_score
        
        # Breach data scoring (0-20 points)
        total_breaches = breach_data.get('total_breaches', 0)
        pastes_count = len(breach_data.get('pastes', []))
        
        breakdown['breaches_count'] = total_breaches
        breakdown['pastes_count'] = pastes_count
        
        # Breach scoring (0-15 points)
        breach_score = 0
        if total_breaches == 0:
            breach_score = 0
        elif total_breaches == 1:
            breach_score = 8
        elif total_breaches <= 3:
            breach_score = 12
        else:
            breach_score = 15
        score += breach_score
        breakdown['breaches'] = breach_score
        
        # Paste scoring (0-5 points)
        paste_score = 0
        if pastes_count == 0:
            paste_score = 0
        elif pastes_count == 1:
            paste_score = 3
        else:
            paste_score = 5
        score += paste_score
        breakdown['pastes'] = paste_score
        
        return min(50, max(0, score)), breakdown
    
    def calculate_risk_score(self, 
                           search_results: Dict[str, List[Dict]], 
                           breach_data: Dict,
                           has_name: bool = False,
                           has_email: bool = False,
                           has_username: bool = False,
                           name: Optional[str] = None,
                           social_results: Optional[Dict] = None,
                           public_records: Optional[Dict] = None,
                           darkweb_data: Optional[Dict] = None,
                           correlation_data: Optional[Dict] = None) -> Dict:
        """
        Calculate total risk score from 0-100 with detailed breakdown.
        
        Returns:
            Dictionary with 'score' and 'breakdown' keys
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
        
        # Additional risk factors
        additional_risk = 0
        
        # Social media exposure weight
        if social_results:
            social_count = sum(len(results) for results in social_results.values())
            if social_count > 10:
                additional_risk += 5
            elif social_count > 5:
                additional_risk += 3
        
        # Public records weight
        if public_records and public_records.get('count', 0) > 0:
            additional_risk += 5
        
        # Dark web risk weight (placeholder)
        if darkweb_data and (darkweb_data.get('breaches') or darkweb_data.get('pastes')):
            additional_risk += 10
        
        # Correlation weight
        if correlation_data and correlation_data.get('total_exposure_count', 0) > 30:
            additional_risk += 5
        
        # Total score is sum of both (0-100), capped
        total_score = min(100, public_score + sensitive_score + additional_risk)
        
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
            'is_famous': is_famous,
            'additional_risk': additional_risk,
            'social_graph_weight': 5 if social_results and sum(len(r) for r in social_results.values()) > 10 else 0,
            'public_records_weight': 5 if public_records and public_records.get('count', 0) > 0 else 0,
            'darkweb_risk_weight': 10 if darkweb_data and (darkweb_data.get('breaches') or darkweb_data.get('pastes')) else 0,
            'correlation_weight': 5 if correlation_data and correlation_data.get('total_exposure_count', 0) > 30 else 0
        }
        
        return {
            'score': total_score,
            'breakdown': breakdown
        }

