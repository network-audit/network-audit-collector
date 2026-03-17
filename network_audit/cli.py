"""CLI entry point — argparse with subcommands dispatching to command modules."""

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
    net_parser.add_argument(
        "-c", "--concurrent", type=int, default=1, help="Max concurrent connections (default: 1)"
    )
    net_parser.add_argument(
        "--delay", type=float, default=0, help="Seconds to wait between launching connections"
    )

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
    linux_parser.add_argument(
        "-c", "--concurrent", type=int, default=1, help="Max concurrent connections (default: 1)"
    )
    linux_parser.add_argument(
        "--delay", type=float, default=0, help="Seconds to wait between launching connections"
    )

    # account subcommand
    acct_parser = subparsers.add_parser(
        "account", help="Check network-audit.io account status"
    )
    acct_parser.add_argument(
        "--account", action="store_true", help="Show account number"
    )
    acct_parser.add_argument(
        "--import-key", action="store_true", help="Import API credentials to ~/.config"
    )
    acct_parser.add_argument(
        "--api-key", nargs="?", const="__show__", default=None,
        metavar="KEY", help="Show current API key, or set a new one"
    )

    # status subcommand
    status_parser = subparsers.add_parser(
        "status", help="Check network-audit.io API status (for scripting/cron)"
    )
    status_parser.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.command == "network":
        from .commands.network import run

        run(args)
    elif args.command == "linux":
        from .commands.linux import run

        run(args)
    elif args.command == "account":
        from .commands.account import run

        run(args)
    elif args.command == "status":
        from .commands.status import run

        run(args)


if __name__ == "__main__":
    main()
