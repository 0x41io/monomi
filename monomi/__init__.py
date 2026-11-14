"""
0x41 / monomi - passive domain reconnaissance with AI synthesis.

This folder is the monomi package. Other tools (like Akashi) import it:

    from monomi import evidence, takeover

The command line lives in monomi/cli.py; monomi.py at the repo root is a
small wrapper so `python monomi.py example.com` keeps working.
"""

from monomi.common import VERSION

__version__ = VERSION
