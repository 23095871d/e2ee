"""
run_server.py - Convenience script to start the Secure IM server.
Run this from the project root directory.

Usage:
    python run_server.py
"""

import sys
import os

# Add project root to Python path so imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from server.app import run_server

if __name__ == "__main__":
    run_server()
