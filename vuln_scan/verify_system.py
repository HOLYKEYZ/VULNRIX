import sys
import os
import json
from dotenv import load_dotenv

# Load env vars
load_dotenv()

# Add project root to path
sys.path.append(os.getcwd())

from engine.pipeline import SecurityPipeline

def verify():
    print("Verifying Vulnrix Modes...")
    
    # Check API Keys
    if not os.getenv("GOOGLE_API_KEY") and not os.getenv("GROQ_KEY"):
        print("ERROR: No API keys found in .env")
        return

    pipeline = SecurityPipeline()
    
    # Create a dummy test file
    with open("test_mode.js", "w") as f:
        f.write("""
        // Vulnerable Code
        const user = req.query.user;
        const sql = "SELECT * FROM users WHERE user = '" + user + "'";
        execute(sql);
        """)

    modes = ["fast", "hybrid", "deep"]
    
    for mode in modes:
        print(f"\n--- Testing Mode: {mode.upper()} ---")
        result = pipeline.scan_file("test_mode.js", mode=mode)
        print(f"Status: {result.get('status')}")
        print(f"Findings: {len(result.get('findings', []))}")
        if result.get('findings'):
            print(f"First Finding: {result['findings'][0]['type']}")

    # Cleanup
    if os.path.exists("test_mode.js"):
        os.remove("test_mode.js")

if __name__ == "__main__":
    verify()
