"""
Correlation analysis module.
"""
from typing import Dict, List, Optional


class CorrelationAnalyzer:
    """Analyzes correlations between different data points."""
    
    def analyze(self, 
                name: Optional[str] = None,
                email: Optional[str] = None,
                username: Optional[str] = None,
                phone: Optional[str] = None,
                search_results: Optional[Dict] = None,
                social_results: Optional[Dict] = None) -> Dict:
        """
        Analyze correlations between provided data points.
        
        Args:
            name: Full name
            email: Email address
            username: Username
            phone: Phone number
            search_results: Web search results
            social_results: Social media scan results
        
        Returns:
            Dictionary with correlation analysis
        """
        correlations = {
            'data_points': [],
            'connections': [],
            'risk_factors': []
        }
        
        # Collect data points
        if name:
            correlations['data_points'].append({'type': 'name', 'value': name})
        if email:
            correlations['data_points'].append({'type': 'email', 'value': email})
        if username:
            correlations['data_points'].append({'type': 'username', 'value': username})
        if phone:
            correlations['data_points'].append({'type': 'phone', 'value': phone})
        
        # Analyze connections
        if email and username:
            local_part = email.split('@')[0] if '@' in email else ''
            if local_part and username and local_part.lower() == username.lower():
                correlations['connections'].append({
                    'type': 'email_username_match',
                    'description': 'Email local part matches username',
                    'risk': 'medium'
                })
                correlations['risk_factors'].append('Email and username correlation increases tracking risk')
        
        if name and email:
            correlations['connections'].append({
                'type': 'name_email_link',
                'description': 'Name and email found together',
                'risk': 'low'
            })
        
        # Count total exposure
        total_exposure = 0
        if search_results:
            total_exposure += len(search_results.get('name', []))
            total_exposure += len(search_results.get('email', []))
            total_exposure += len(search_results.get('username', []))
        
        if social_results:
            for platform_results in social_results.values():
                total_exposure += len(platform_results)
        
        correlations['total_exposure_count'] = total_exposure
        
        if total_exposure > 20:
            correlations['risk_factors'].append('High total exposure across multiple platforms')
        
        return correlations

