#!/usr/bin/env python3
"""Backward-compat wrapper — delegates to network_audit.commands.account."""

from network_audit.commands.account import run


def parse_args():
    import argparse

    parser = argparse.ArgumentParser(
        description="Check your Network-Audit.io account status."
    )
    parser.add_argument("--account", action="store_true", help="Show account number")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    run(args)
