"""
Vulnrix Next-Gen Launcher
"""
import sys
import os

def print_help():
    print("Vulnrix Next-Gen Launcher")
    print("Usage:")
    print("  python main.py dashboard   # Start Web Dashboard")
    print("  python main.py node        # Start Distributed Node")
    print("  python main.py help        # Show this message")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)
        
    cmd = sys.argv[1]
    
    if cmd == "dashboard":
        print("Starting Web Dashboard...")
        os.system(f"{sys.executable} web_dashboard/app.py")
    elif cmd == "node":
        print("Starting Node Server...")
        os.system(f"{sys.executable} nodes/server.py")
    else:
        print_help()
