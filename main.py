"""
Digital Footprint Shield - Main Entry Point
A privacy-first tool that scans the internet for exposed personal data.
"""

import os
import sys
from typing import Optional, Tuple
from colorama import Fore, Style

from utils.display import (
    print_banner, print_disclaimer, print_section_header,
    print_safe, print_warning, print_danger, print_info,
    print_result_label, format_risk_score, print_separator,
    print_breakdown_header, print_breakdown_component, format_component_score
)
from search_engine import SearchEngine
from breach_check import BreachChecker
from risk_analyzer import RiskAnalyzer
from privacy_advisor import PrivacyAdvisor
from api_key_manager import APIKeyManager, get_api_key_for_search


def get_user_input() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Prompt user for name, email, or username.
    
    Returns:
        Tuple of (name, email, username) - any can be None
    """
    print_section_header("INPUT YOUR INFORMATION")
    print_info("Enter the information you want to check. You can provide any combination:")
    print_info("  • Name (e.g., John Doe)")
    print_info("  • Email (e.g., john@example.com)")
    print_info("  • Username (e.g., johndoe123)")
    print_info("\nPress Enter to skip any field.\n")
    
    name = input(f"{'Name: '}").strip() or None
    email = input(f"{'Email: '}").strip() or None
    username = input(f"{'Username: '}").strip() or None
    
    if not name and not email and not username:
        print_danger("\n❌ Error: You must provide at least one field (name, email, or username).")
        return None, None, None
    
    return name, email, username


def main():
    """Main function to run Digital Footprint Shield."""
    # Set terminal background to black (if supported)
    os.system('color 0F' if sys.platform == 'win32' else '')
    
    # Display banner and disclaimer
    print_banner()
    print_disclaimer()
    
    # Get user input
    name, email, username = get_user_input()
    if not name and not email and not username:
        return
    
    # Initialize API Key Manager
    key_manager = APIKeyManager()
    
    # Get Google API key & CSE ID dynamically
    google_api_key, google_search_engine_id = get_api_key_for_search(key_manager)
    
    if not google_api_key or not google_search_engine_id:
        print_warning("⚠️ Google Custom Search unavailable. Web scan will be skipped.")
    
    # Initialize components
    search_engine = SearchEngine(google_api_key, google_search_engine_id)
    breach_checker = BreachChecker()
    risk_analyzer = RiskAnalyzer()
    privacy_advisor = PrivacyAdvisor(None)  # HIBP or Grok optional; keep None if no key
    
    # Perform searches
    print_section_header("SCANNING IN PROGRESS")
    print_info("Please wait while we scan the internet for your information...\n")
    
    search_results = search_engine.find_mentions(name=name, email=email, username=username)
    
    # Check breaches (only if email provided)
    breach_data = {'breaches': [], 'pastes': [], 'total_breaches': 0}
    if email:
        breach_data = breach_checker.check_email(email, None)  # HIBP key optional
    
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
    
    # Display results
    print("\n" + "=" * 60)
    print_section_header("SCAN RESULTS")
    
    display_search_results(search_results)
    
    if email:
        display_breach_results(breach_data)
    
    # Display risk breakdown
    display_risk_breakdown(breakdown)
    
    # Display recommendations
    display_risk_assessment(risk_score, recommendations)
    
    # Final message
    print_separator()
    print_info("\n✨ Scan complete! Remember: All scans are local. No data is stored.")
    print_info("Thank you for using Digital Footprint Shield! 🛡️\n")


def display_search_results(search_results: dict):
    """Display formatted search results."""
    print_section_header("WEB SEARCH RESULTS")
    
    for result_type, results in search_results.items():
        if not results:
            continue
        
        type_label = result_type.capitalize()
        print_info(f"\n{type_label} Mentions Found: {len(results)}")
        print_separator()
        
        for i, result in enumerate(results, 1):
            print(f"\n  {i}. {result.get('title', 'No title')}")
            print(f"     {result.get('link', 'No link')}")
            snippet = result.get('snippet', 'No snippet available')
            if len(snippet) > 150:
                snippet = snippet[:150] + "..."
            print(f"     {snippet}")
    
    if not any(search_results.values()):
        print_safe("✅ No online mentions found in search results.")


def display_breach_results(breach_data: dict):
    """Display formatted breach check results."""
    print_section_header("DATA BREACH CHECK")
    
    total_breaches = breach_data.get('total_breaches', 0)
    pastes_count = len(breach_data.get('pastes', []))
    
    if total_breaches > 0:
        print_danger(f"🚨 Found {total_breaches} data breach(es):")
        for breach in breach_data.get('breaches', []):
            breach_name = breach.get('Name', 'Unknown')
            breach_date = breach.get('BreachDate', 'Unknown')
            breach_domain = breach.get('Domain', 'Unknown')
            print_danger(f"  • {breach_name} ({breach_domain}) - Breached: {breach_date}")
    else:
        print_safe("✅ No known data breaches found.")
    
    if pastes_count > 0:
        print_warning(f"⚠️  Found {pastes_count} paste(s) containing this email:")
        for paste in breach_data.get('pastes', []):
            paste_source = paste.get('Source', 'Unknown')
            paste_id = paste.get('Id', 'Unknown')
            print_warning(f"  • {paste_source} (ID: {paste_id})")
    else:
        print_safe("✅ No pastes found.")


def display_risk_breakdown(breakdown: dict):
    """Display detailed risk breakdown with Public and Sensitive Exposure."""
    print_breakdown_header()
    
    total_score = breakdown.get('total_score', 0)
    public_exposure = breakdown.get('public_exposure', {})
    sensitive_exposure = breakdown.get('sensitive_exposure', {})
    is_famous = breakdown.get('is_famous', False)
    
    public_score = public_exposure.get('score', 0)
    sensitive_score = sensitive_exposure.get('score', 0)
    
    public_breakdown = public_exposure.get('breakdown', {})
    sensitive_breakdown = sensitive_exposure.get('breakdown', {})
    
    # Public Exposure breakdown
    print_info(f"{Style.BRIGHT}Public Exposure (0-50):{Style.RESET_ALL}")
    name_mentions = public_breakdown.get('name_mentions_count', 0)
    name_score = public_breakdown.get('name_mentions', 0)
    fame_adjustment = public_breakdown.get('fame_adjustment', 0)
    
    if is_famous:
        print_breakdown_component(
            "Name Mentions", name_score, 30,
            f"Found {name_mentions} mentions (Fame adjustment: -{fame_adjustment} points)",
            "warning" if public_score > 20 else "safe"
        )
        print_info(f"    {Fore.CYAN}ℹ️  Public figure detected. Public mentions are expected.{Style.RESET_ALL}")
    else:
        print_breakdown_component(
            "Name Mentions", name_score, 30,
            f"Found {name_mentions} mentions",
            "danger" if public_score > 20 else "warning" if public_score > 10 else "safe"
        )
    
    print_breakdown_component(
        "Total Public Exposure", public_score, 50,
        "",
        "danger" if public_score > 30 else "warning" if public_score > 15 else "safe"
    )
    
    print_separator()
    
    # Sensitive Exposure breakdown
    print_info(f"{Style.BRIGHT}Sensitive Exposure (0-50):{Style.RESET_ALL}")
    
    email_mentions = sensitive_breakdown.get('email_mentions_count', 0)
    email_score = sensitive_breakdown.get('email_mentions', 0)
    if email_score > 0:
        print_breakdown_component(
            "Email Mentions", email_score, 15,
            f"Found {email_mentions} mentions - CRITICAL RISK",
            "danger"
        )
    
    username_mentions = sensitive_breakdown.get('username_mentions_count', 0)
    username_score = sensitive_breakdown.get('username_mentions', 0)
    if username_score > 0:
        print_breakdown_component(
            "Username Mentions", username_score, 10,
            f"Found {username_mentions} mentions",
            "warning" if username_score > 5 else "safe"
        )
    
    breaches_count = sensitive_breakdown.get('breaches_count', 0)
    breaches_score = sensitive_breakdown.get('breaches', 0)
    if breaches_score > 0:
        print_breakdown_component(
            "Data Breaches", breaches_score, 15,
            f"Found {breaches_count} breach(es) - CRITICAL RISK",
            "danger"
        )
    
    pastes_count = sensitive_breakdown.get('pastes_count', 0)
    pastes_score = sensitive_breakdown.get('pastes', 0)
    if pastes_score > 0:
        print_breakdown_component(
            "Pastes Found", pastes_score, 5,
            f"Found {pastes_count} paste(s)",
            "warning" if pastes_score > 2 else "safe"
        )
    
    print_breakdown_component(
        "Total Sensitive Exposure", sensitive_score, 50,
        "",
        "danger" if sensitive_score > 30 else "warning" if sensitive_score > 15 else "safe"
    )
    
    print_separator()
    
    # Total Risk Score
    print_info(f"\n{Style.BRIGHT}Total Risk Score:{Style.RESET_ALL}")
    print_result_label(
        "Overall Risk", format_risk_score(total_score),
        "safe" if total_score <= 30 else "warning" if total_score <= 70 else "danger"
    )
    print_info(f"  Public Exposure: {format_component_score(public_score, 50)}")
    print_info(f"  Sensitive Exposure: {format_component_score(sensitive_score, 50)}")


def display_risk_assessment(score: int, recommendations: list):
    """Display risk assessment and recommendations."""
    print_section_header("PRIVACY RECOMMENDATIONS")
    
    print_info("\n💡 Actionable Recommendations:")
    for i, rec in enumerate(recommendations, 1):
        print(f"  {i}. {rec}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print_danger(f"\n❌ An unexpected error occurred: {str(e)}")
        sys.exit(1)
