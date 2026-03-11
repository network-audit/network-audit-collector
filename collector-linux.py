#!/usr/bin/env python3
"""Backward-compat wrapper — delegates to network_audit.commands.linux."""

from network_audit.commands.linux import run


def parse_args():
    import argparse

    parser = argparse.ArgumentParser(description="Linux Collector for network-audit.io")
    parser.add_argument(
        "-i",
        "--inventory",
        default="linux-inv.json",
        help="Inventory JSON file (default: linux-inv.json)",
    )
    parser.add_argument(
        "-u", "--username", default="root", help="SSH username (default: root)"
    )
    parser.add_argument(
        "--ask-pass",
        action="store_true",
        help="Prompt for SSH password instead of key auth",
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=10, help="SSH timeout in seconds"
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="CSV output filename (default: linux_audit_<timestamp>.csv)",
    )
    parser.add_argument("--debug", action="store_true", help="Print raw API responses")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(args)
