"""
Display utilities for Digital Footprint Shield.
Handles ASCII art, color themes, and formatted output.
"""

import colorama
from colorama import Fore, Back, Style

# Initialize colorama
colorama.init(autoreset=True)


def print_banner():
    """Display the ASCII banner for Digital Footprint Shield."""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     🛡️  DIGITAL FOOTPRINT SHIELD – Protect Your Privacy  🛡️   ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)


def print_disclaimer():
    """Display the privacy disclaimer."""
    disclaimer = f"""
{Fore.CYAN}{Style.BRIGHT}⚠️  PRIVACY DISCLAIMER:{Style.RESET_ALL}
{Fore.WHITE}All scans are local. No data is stored or sent anywhere.
Your privacy is our top priority.{Style.RESET_ALL}

"""
    print(disclaimer)


def print_section_header(text):
    """Print a formatted section header."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'=' * 60}")
    print(f"{text}")
    print(f"{'=' * 60}{Style.RESET_ALL}\n")


def print_safe(text):
    """Print text in green (safe)."""
    print(f"{Fore.GREEN}{text}{Style.RESET_ALL}")


def print_warning(text):
    """Print text in yellow (warning)."""
    print(f"{Fore.YELLOW}{text}{Style.RESET_ALL}")


def print_danger(text):
    """Print text in red (danger)."""
    print(f"{Fore.RED}{Style.BRIGHT}{text}{Style.RESET_ALL}")


def print_info(text):
    """Print text in cyan (info)."""
    print(f"{Fore.CYAN}{text}{Style.RESET_ALL}")


def print_result_label(label, value, risk_level="info"):
    """Print a formatted result label-value pair."""
    formatted_label = f"{Fore.WHITE}{Style.BRIGHT}{label}:{Style.RESET_ALL}"
    
    if risk_level == "safe":
        formatted_value = f"{Fore.GREEN}{value}{Style.RESET_ALL}"
    elif risk_level == "warning":
        formatted_value = f"{Fore.YELLOW}{value}{Style.RESET_ALL}"
    elif risk_level == "danger":
        formatted_value = f"{Fore.RED}{Style.BRIGHT}{value}{Style.RESET_ALL}"
    else:
        formatted_value = f"{Fore.CYAN}{value}{Style.RESET_ALL}"
    
    print(f"  {formatted_label} {formatted_value}")


def format_risk_score(score):
    """Format risk score with appropriate color."""
    if score <= 30:
        return f"{Fore.GREEN}{Style.BRIGHT}{score}/100 (Safe){Style.RESET_ALL}"
    elif score <= 70:
        return f"{Fore.YELLOW}{Style.BRIGHT}{score}/100 (Medium Risk){Style.RESET_ALL}"
    else:
        return f"{Fore.RED}{Style.BRIGHT}{score}/100 (High Risk){Style.RESET_ALL}"


def print_separator():
    """Print a visual separator line."""
    print(f"{Fore.CYAN}{'-' * 60}{Style.RESET_ALL}")


def print_breakdown_header():
    """Print header for risk breakdown section."""
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'─' * 60}")
    print(f"{'RISK BREAKDOWN'}")
    print(f"{'─' * 60}{Style.RESET_ALL}\n")


def print_breakdown_component(label: str, score: int, max_score: int, 
                              details: str = "", risk_level: str = "info"):
    """
    Print a breakdown component with score and details.
    
    Args:
        label: Component label
        score: Component score
        max_score: Maximum possible score for this component
        details: Additional details string
        risk_level: Risk level ('safe', 'warning', 'danger', 'info')
    """
    percentage = (score / max_score * 100) if max_score > 0 else 0
    score_str = f"{score}/{max_score}"
    
    # Format label
    formatted_label = f"{Fore.WHITE}{Style.BRIGHT}{label}:{Style.RESET_ALL}"
    
    # Format score based on risk level
    if risk_level == "safe":
        formatted_score = f"{Fore.GREEN}{score_str} ({percentage:.0f}%){Style.RESET_ALL}"
    elif risk_level == "warning":
        formatted_score = f"{Fore.YELLOW}{score_str} ({percentage:.0f}%){Style.RESET_ALL}"
    elif risk_level == "danger":
        formatted_score = f"{Fore.RED}{Style.BRIGHT}{score_str} ({percentage:.0f}%){Style.RESET_ALL}"
    else:
        formatted_score = f"{Fore.CYAN}{score_str} ({percentage:.0f}%){Style.RESET_ALL}"
    
    print(f"  {formatted_label} {formatted_score}")
    
    if details:
        print(f"    {Fore.WHITE}{details}{Style.RESET_ALL}")


def format_component_score(score: int, max_score: int) -> str:
    """
    Format a component score with color based on percentage.
    
    Args:
        score: Component score
        max_score: Maximum possible score
    
    Returns:
        Formatted score string
    """
    percentage = (score / max_score * 100) if max_score > 0 else 0
    
    if percentage <= 30:
        return f"{Fore.GREEN}{score}/{max_score} ({percentage:.0f}%){Style.RESET_ALL}"
    elif percentage <= 70:
        return f"{Fore.YELLOW}{score}/{max_score} ({percentage:.0f}%){Style.RESET_ALL}"
    else:
        return f"{Fore.RED}{Style.BRIGHT}{score}/{max_score} ({percentage:.0f}%){Style.RESET_ALL}"

