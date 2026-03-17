#!/usr/bin/env python3
"""Unified CLI for network-audit-collector (aws-cli style).

Usage:
    python main.py network -u admin --ask-pass -i inv.json
    python main.py linux -i linux-inv.json
    python main.py account
"""

from network_audit.cli import main

if __name__ == "__main__":
    main()
