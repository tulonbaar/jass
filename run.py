#!/usr/bin/env python3
"""
JASS - Just Another System Sniffer
Main Launcher Script (CLI & Web UI)
"""

import sys
from jass.cli import run_cli

if __name__ == "__main__":
    sys.exit(run_cli())

