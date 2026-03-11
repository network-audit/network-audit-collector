"""CLI entry point — argparse with subcommands dispatching to command modules."""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="network-audit",
        description="Network & Linux audit tools powered by network-audit.io",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- network subcommand ---
    net = subparsers.add_parser("network", help="Scan Cisco devices (SSH/Telnet)")
    net.add_argument("--ask-pass", action="store_true", required=True,
                     help="Prompt for SSH password")
    net.add_argument("--telnet", action="store_true",
                     help="Use Telnet instead of SSH")
    net.add_argument("-u", "--username", required=True, help="SSH/Telnet username")
    net.add_argument("-i", "--inventory", default="inv.json", help="Inventory JSON file")
    net.add_argument("-t", "--timeout", type=int, default=10, help="SSH timeout in seconds")
    net.add_argument("-o", "--output", default=None,
                     help="CSV output filename (default: data/<timestamp>_network.csv)")

    # --- linux subcommand ---
    lin = subparsers.add_parser("linux", help="Scan Linux hosts (SSH)")
    lin.add_argument("-i", "--inventory", default="linux-inv.json",
                     help="Inventory JSON file (default: linux-inv.json)")
    lin.add_argument("-u", "--username", default="root",
                     help="SSH username (default: root)")
    lin.add_argument("--ask-pass", action="store_true",
                     help="Prompt for SSH password instead of key auth")
    lin.add_argument("-t", "--timeout", type=int, default=10,
                     help="SSH timeout in seconds")
    lin.add_argument("-o", "--output", default=None,
                     help="CSV output filename (default: data/<timestamp>_linux.csv)")
    lin.add_argument("--debug", action="store_true",
                     help="Print raw API responses")

    # --- account subcommand ---
    acct = subparsers.add_parser("account", help="Check network-audit.io account status")
    acct.add_argument("--account", action="store_true", help="Show account number")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "network":
        from .commands.network import run
    elif args.command == "linux":
        from .commands.linux import run
    elif args.command == "account":
        from .commands.account import run

    run(args)


if __name__ == "__main__":
    main()
