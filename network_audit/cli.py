"""CLI entry point — argparse with subcommands dispatching to command modules."""

import argparse
import getpass
import os
import sys


def _interactive_mode():
    """Menu-driven scan when invoked with no arguments."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm

    console = Console()
    console.print(Panel("[bold cyan]Network Audit Collector[/]\n[dim]Powered by network-audit.io[/]",
                        expand=False))

    scan_type = Prompt.ask("Scan type", choices=["network", "linux"])

    # --- Inventory ---
    defaults = {"network": "inv.json", "linux": "linux-inv.json"}
    inventory = Prompt.ask("Inventory file or IP", default=defaults[scan_type])

    # If user typed a bare IP/hostname (not a file path), wrap it in a temp inventory
    if not os.path.exists(inventory) and not inventory.endswith((".json", ".csv")):
        import json
        import tempfile
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump([{"host": inventory, "name": inventory}], tmp)
        tmp.close()
        inventory = tmp.name

    # --- Username ---
    if scan_type == "linux":
        username = Prompt.ask("Username", default=getpass.getuser())
    else:
        username = Prompt.ask("Username")

    # --- Auth ---
    if scan_type == "linux":
        auth = Prompt.ask("Auth", choices=["key", "password"], default="key")
        ask_pass = auth == "password"
    else:
        ask_pass = True

    # --- Scan-type-specific options ---
    sysinfo = False
    if scan_type == "linux":
        sysinfo = Confirm.ask("Collect sysinfo?", default=False)

    # --- Concurrency & timeout ---
    from rich.prompt import IntPrompt
    concurrent = IntPrompt.ask("Concurrent connections", default=1)
    timeout = IntPrompt.ask("Timeout (seconds)", default=10)

    # --- Output ---
    output = Prompt.ask("Output", choices=["rich", "json"], default="rich")

    # Build an args namespace matching what the subcommand run() expects
    args = argparse.Namespace(
        command=scan_type,
        inventory=inventory,
        username=username,
        ask_pass=ask_pass,
        timeout=timeout,
        output=None,
        json=(output == "json"),
        no_csv=(output == "json"),
        no_rich=False,
        concurrent=concurrent,
        delay=0,
        sysinfo=sysinfo,
        no_api=False,
        debug=False,
        dev=False,
    )

    # Network-specific defaults
    if scan_type == "network":
        args.telnet = False

    return args


def main():
    # If no arguments at all, launch interactive mode
    if len(sys.argv) == 1:
        try:
            args = _interactive_mode()
        except KeyboardInterrupt:
            print("\nCancelled.")
            return

        if args.command == "network":
            from .commands.network import run
        elif args.command == "linux":
            from .commands.linux import run
        run(args)
        return

    parser = argparse.ArgumentParser(
        description="Network Audit Collector - unified CLI for network-audit.io"
    )
    parser.add_argument(
        "--version", action="version",
        version="network-audit-collector 0.1.0 — https://network-audit.io (manage account & API credits)",
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
    net_parser.add_argument(
        "--dev", nargs="?", const="local", default=None, metavar="TARGET",
        help="Use alternate API: dev, local (default), or an IP/URL"
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
    linux_parser.add_argument("--json", action="store_true", help="Output results as JSON to stdout")
    linux_parser.add_argument("--no-csv", action="store_true", help="Skip CSV file export")
    linux_parser.add_argument("--no-rich", action="store_true", help="Suppress Rich console output (banner, progress, table)")
    linux_parser.add_argument(
        "--sysinfo", action="store_true", help="Collect CPU, memory, storage, and uptime"
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
    linux_parser.add_argument(
        "--dev", nargs="?", const="local", default=None, metavar="TARGET",
        help="Use alternate API: dev, local (default), or an IP/URL"
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
    acct_parser.add_argument("--json", action="store_true", default=True, help="Output as JSON (default)")
    acct_parser.add_argument("--rich", action="store_true", help="Show Rich table instead of JSON")

    # status subcommand
    status_parser = subparsers.add_parser(
        "status", help="Check network-audit.io API status (for scripting/cron)"
    )
    status_parser.add_argument(
        "--json", action="store_true", default=True, help="Output machine-readable JSON (default)"
    )
    status_parser.add_argument(
        "--rich", action="store_true", help="Show Rich panel instead of JSON"
    )

    # update subcommand
    subparsers.add_parser(
        "update", help="Update collector to the latest version"
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
    elif args.command == "update":
        from .commands.update import run

        run(args)


if __name__ == "__main__":
    main()
