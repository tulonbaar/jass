#!/usr/bin/env python3
"""
JASS - Just Another System Sniffer
Skrypt uruchomieniowy (CLI & Web UI Launcher)
"""

import sys
from jass.cli import run_cli

if __name__ == "__main__":
    sys.exit(run_cli())
