#!/usr/bin/env python3
"""
Runs the monomi command line: python monomi.py example.com

The code lives in the monomi/ package (monomi/cli.py). This file stays at the
repo root so existing commands keep working. Python picks the monomi/ folder
over this file when the code below says "from monomi", so the two don't clash.
"""

import sys

from monomi.cli import main

if __name__ == "__main__":
    sys.exit(main())
