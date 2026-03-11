#!/usr/bin/env python3
"""Unified CLI for network-audit-collector (aws-cli style).

Usage:
    python main.py network -u admin --ask-pass -i inv.json
    python main.py linux -i linux-inv.json
    python main.py account
"""

import argparse
import getpass


def main():
    parser = argparse.ArgumentParser(
        description="Network Audit Collector - unified CLI for network-audit.io"
    )
    subparsers = parser.add_subparsers(dest="command")

    # network subcommand
    net_parser = subparsers.add_parser(
        "network", help="Scan Cisco network devices (SSH/Telnet)"
    )
    net_parser.add_argument(
        "--ask-pass",
        action="store_true",
        required=True,
        help="Prompt for SSH/Telnet password",
    )
    net_parser.add_argument(
        "--telnet", action="store_true", help="Use Telnet instead of SSH"
    )
    net_parser.add_argument(
        "-u", "--username", required=True, help="SSH/Telnet username"
    )
    net_parser.add_argument(
        "-i", "--inventory", default="inv.json", help="Inventory JSON file"
    )
    net_parser.add_argument(
        "-t", "--timeout", type=int, default=10, help="Connection timeout in seconds"
    )
    net_parser.add_argument("-o", "--output", default=None, help="CSV output filename")

    # linux subcommand
    linux_parser = subparsers.add_parser("linux", help="Scan Linux hosts (SSH)")
    linux_parser.add_argument(
        "-i", "--inventory", default="linux-inv.json", help="Inventory JSON file"
    )
    linux_parser.add_argument("-u", "--username", default=getpass.getuser(), help="SSH username")
    linux_parser.add_argument(
        "--ask-pass",
        action="store_true",
        help="Prompt for SSH password instead of key auth",
    )
    linux_parser.add_argument(
        "-t", "--timeout", type=int, default=10, help="SSH timeout in seconds"
    )
    linux_parser.add_argument(
        "-o", "--output", default=None, help="CSV output filename"
    )
    linux_parser.add_argument(
        "--debug", action="store_true", help="Print raw API responses"
    )

    # account subcommand
    acct_parser = subparsers.add_parser(
        "account", help="Check network-audit.io account status"
    )
    acct_parser.add_argument(
        "--account", action="store_true", help="Show account number"
    )

    # status subcommand
    subparsers.add_parser(
        "status", help="Check network-audit.io API status (for scripting/cron)"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "network":
        from network_audit.commands.network import run

        run(args)
    elif args.command == "linux":
        from network_audit.commands.linux import run

        run(args)
    elif args.command == "account":
        from network_audit.commands.account import run

        run(args)
    elif args.command == "status":
        from network_audit.commands.status import run

        run(args)


if __name__ == "__main__":
    main()
