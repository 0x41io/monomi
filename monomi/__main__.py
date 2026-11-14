"""Lets `python -m monomi example.com` run the command line."""

import sys

from monomi.cli import main

if __name__ == "__main__":
    sys.exit(main())
