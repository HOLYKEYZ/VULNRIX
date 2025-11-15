"""
Flask web application for Digital Footprint Shield.
Provides a web interface for privacy scanning.
"""

from flask import Flask, render_template, request, jsonify
import os
import sys
from typing import Optional, Tuple
from dotenv import load_dotenv

# Load environment variables from .env file (for local development)
load_dotenv()

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

from search_engine import SearchEngine
from breach_check import BreachChecker
from risk_analyzer import RiskAnalyzer
from privacy_advisor import PrivacyAdvisor

app = Flask(__name__)
# Use FLASK_SECRET_KEY from environment if available, otherwise generate one
flask_secret = os.getenv('FLASK_SECRET_KEY')
if flask_secret:
    app.config['SECRET_KEY'] = flask_secret
else:
    app.config['SECRET_KEY'] = os.urandom(24).hex()


class ConfigurationError(Exception):
    """Raised when required environment variables are missing."""
    pass


def load_api_config() -> Tuple[str, str, Optional[str], Optional[str]]:
    """
    Load API configuration from environment variables only.
    
    Returns:
        Tuple of (google_api_key, google_search_engine_id, hibp_api_key, grok_api_key)
    
    Raises:
        ConfigurationError: If required environment variables are missing
    """
    google_api_key = os.getenv('GOOGLE_API_KEY')
    google_search_engine_id = os.getenv('CSE_ID')  # Using CSE_ID as requested
    hibp_api_key = os.getenv('HIBP_API_KEY')
    grok_api_key = os.getenv('GROK_API_KEY')
    
    # Validate required environment variables
    if not google_api_key:
        raise ConfigurationError(
            "GOOGLE_API_KEY environment variable is required. "
            "Please set it in your environment or Render dashboard."
        )
    
    if not google_search_engine_id:
        raise ConfigurationError(
            "CSE_ID environment variable is required. "
            "Please set it in your environment or Render dashboard."
        )
    
    return google_api_key, google_search_engine_id, hibp_api_key, grok_api_key

def format_risk_level(score: int) -> dict:
    """
    Format risk score with color and level.
    
    Args:
        score: Risk score from 0-100
    
    Returns:
        Dictionary with score, level, color, and class
    """
    if score <= 30:
        return {
            'score': score,
            'level': 'Safe',
            'color': '#10b981',  # green
            'class': 'safe'
        }
    elif score <= 70:
        return {
            'score': score,
            'level': 'Medium Risk',
            'color': '#f59e0b',  # yellow
            'class': 'warning'
        }
    else:
        return {
            'score': score,
            'level': 'High Risk',
            'color': '#ef4444',  # red
            'class': 'danger'
        }


@app.route('/')
def home():
    """Home page with input form."""
    return render_template('home.html')


@app.route('/results')
def results():
    """Display scan results page."""
    return render_template('results.html', results=None, error=None)


@app.route('/scan', methods=['POST'])
def scan():
    """
    Perform privacy scan and return results.
    Handles both JSON and form submissions.
    """
    try:
        # Get input data
        if request.is_json:
            data = request.get_json()
            name = data.get('name', '').strip() or None
            email = data.get('email', '').strip() or None
            username = data.get('username', '').strip() or None
        else:
            name = request.form.get('name', '').strip() or None
            email = request.form.get('email', '').strip() or None
            username = request.form.get('username', '').strip() or None
        
        # Validate input
        if not name and not email and not username:
            error_msg = 'Please provide at least one field (name, email, or username).'
            if request.is_json:
                return jsonify({'error': error_msg}), 400
            else:
                return render_template('results.html', results=None, error=error_msg), 400
        
        # Load API configuration - will raise ConfigurationError if env vars missing
        try:
            google_api_key, google_search_engine_id, hibp_api_key, grok_api_key = load_api_config()
        except ConfigurationError as e:
            error_msg = str(e)
            if request.is_json:
                return jsonify({'error': error_msg}), 500
            else:
                return render_template('results.html', results=None, error=error_msg), 500
        
        # Initialize components
        search_engine = SearchEngine(google_api_key, google_search_engine_id)
        breach_checker = BreachChecker()
        risk_analyzer = RiskAnalyzer()
        privacy_advisor = PrivacyAdvisor(grok_api_key)
        
        # Perform searches
        search_results = search_engine.find_mentions(name=name, email=email, username=username)
        
        # Check breaches (only if email provided)
        breach_data = {'breaches': [], 'pastes': [], 'total_breaches': 0}
        if email:
            breach_data = breach_checker.check_email(email, hibp_api_key)
        
        # Calculate risk score with breakdown
        risk_score, breakdown = risk_analyzer.calculate_risk_score(
            search_results=search_results,
            breach_data=breach_data,
            has_name=bool(name),
            has_email=bool(email),
            has_username=bool(username),
            name=name
        )
        
        # Get AI-powered recommendations
        recommendations = privacy_advisor.get_recommendations(
            breakdown, search_results, breach_data
        )
        
        # Format results for display
        formatted_results = {
            'input': {
                'name': name or '',
                'email': email or '',
                'username': username or ''
            },
            'search_results': {
                'name': search_results.get('name', []),
                'email': search_results.get('email', []),
                'username': search_results.get('username', [])
            },
            'breach_data': {
                'breaches': breach_data.get('breaches', []),
                'pastes': breach_data.get('pastes', []),
                'total_breaches': breach_data.get('total_breaches', 0)
            },
            'risk_score': format_risk_level(risk_score),
            'breakdown': {
                'total_score': breakdown.get('total_score', 0),
                'public_exposure': {
                    'score': breakdown.get('public_exposure', {}).get('score', 0),
                    'breakdown': breakdown.get('public_exposure', {}).get('breakdown', {})
                },
                'sensitive_exposure': {
                    'score': breakdown.get('sensitive_exposure', {}).get('score', 0),
                    'breakdown': breakdown.get('sensitive_exposure', {}).get('breakdown', {})
                },
            'is_famous': breakdown.get('is_famous', False)
            },
            'recommendations': recommendations
        }
        
        # Return JSON for AJAX or render template
        if request.is_json:
            return jsonify(formatted_results)
        else:
            return render_template('results.html', results=formatted_results)
    
    except Exception as e:
        error_msg = f"An error occurred during scanning: {str(e)}"
        if request.is_json:
            return jsonify({'error': error_msg}), 500
        else:
            return render_template('results.html', error=error_msg), 500


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for programmatic access."""
    return scan()


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
