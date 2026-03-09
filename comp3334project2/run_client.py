"""
run_client.py - Convenience script to start the Secure IM client.
Run this from the project root directory.

Usage:
    python run_client.py [--server https://localhost:5000]
"""

import sys
import os

# Add project root to Python path so imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from client.main import main

if __name__ == "__main__":
    main()
