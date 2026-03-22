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
    net_parser.add_argument("--json", action="store_true", help="Output results as JSON to stdout")
    net_parser.add_argument("--no-csv", action="store_true", help="Skip CSV file export")
    net_parser.add_argument("--no-rich", action="store_true", help="Suppress Rich console output (banner, progress, table)")
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
    linux_parser.add_argument("--json", action="store_true", default=True, help="Output results as JSON to stdout")
    linux_parser.add_argument("--no-csv", action="store_true", default=True, help="Skip CSV file export")
    linux_parser.add_argument("--no-rich", action="store_true", default=True, help="Suppress Rich console output (banner, progress, table)")
    linux_parser.add_argument(
        "--patched", action="store_true", help="Check last patched date on each host"
    )
    linux_parser.add_argument(
        "--sysinfo", action="store_true", help="Collect CPU, memory, storage, and uptime"
    )
    linux_parser.add_argument(
        "--cve", action="store_true", help="Check installed packages for known CVEs (implies --sysinfo)"
    )
    linux_parser.add_argument(
        "--no-api", action="store_true", help="Skip EOL API lookups (useful with --sysinfo)"
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

    # windows subcommand
    win_parser = subparsers.add_parser("windows", help="Scan Windows hosts (WinRM, or SSH with --ssh)")
    win_parser.add_argument(
        "-i", "--inventory", default="windows-inv.json", help="Inventory JSON file"
    )
    win_parser.add_argument("-u", "--username", required=True, help="Username")
    win_parser.add_argument(
        "--ask-pass",
        action="store_true",
        required=True,
        help="Prompt for password",
    )
    win_parser.add_argument(
        "--ssh", action="store_true",
        help="Use SSH instead of WinRM (requires OpenSSH on target)",
    )
    win_parser.add_argument(
        "--https", action="store_true",
        help="Use HTTPS for WinRM (port 5986 instead of 5985)",
    )
    win_parser.add_argument(
        "--ntlm", action="store_true",
        help="Use NTLM auth for WinRM (default is basic auth)",
    )
    win_parser.add_argument(
        "-t", "--timeout", type=int, default=10, help="Connection timeout in seconds"
    )
    win_parser.add_argument("-o", "--output", default=None, help="CSV output filename")
    win_parser.add_argument("--json", action="store_true", help="Output results as JSON to stdout")
    win_parser.add_argument("--no-csv", action="store_true", help="Skip CSV file export")
    win_parser.add_argument("--no-rich", action="store_true", help="Suppress Rich console output (banner, progress, table)")
    win_parser.add_argument(
        "--sysinfo", action="store_true", help="Collect CPU, memory, storage, and uptime"
    )
    win_parser.add_argument(
        "--no-api", action="store_true", help="Skip EOL API lookups (useful with --sysinfo)"
    )
    win_parser.add_argument(
        "--debug", action="store_true", help="Print raw API responses"
    )
    win_parser.add_argument(
        "-c", "--concurrent", type=int, default=1, help="Max concurrent connections (default: 1)"
    )
    win_parser.add_argument(
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
    acct_parser.add_argument("--json", action="store_true", help="Output results as JSON to stdout")

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
    elif args.command == "windows":
        from .commands.windows import run

        run(args)
    elif args.command == "account":
        from .commands.account import run

        run(args)
    elif args.command == "status":
        from .commands.status import run

        run(args)


if __name__ == "__main__":
    main()
