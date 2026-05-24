#!/usr/bin/env python3
"""
FlowWatch AI - Production Entry Point
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.app.main import main

if __name__ == "__main__":
    main()
