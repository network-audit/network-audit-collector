#!/usr/bin/env python3
"""Backward-compat wrapper — delegates to network_audit.commands.network."""

from network_audit.commands.network import run


def parse_args():
    import argparse

    parser = argparse.ArgumentParser(
        description="Network Collector for network-audit.io"
    )
    parser.add_argument(
        "--ask-pass", action="store_true", required=True, help="Prompt for SSH password"
    )
    parser.add_argument(
        "--telnet", action="store_true", help="Use Telnet instead of SSH"
    )
    parser.add_argument("-u", "--username", required=True, help="SSH/Telnet username")
    parser.add_argument(
        "-i", "--inventory", default="inv.json", help="Inventory JSON file"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=10, help="SSH timeout in seconds"
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="CSV output filename (default: network_audit_<timestamp>.csv)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(args)
