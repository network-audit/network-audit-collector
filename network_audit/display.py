"""Shared Rich display helpers."""

import sys

from rich.console import Console, Group
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

console = Console()


def redirect_console_to_stderr():
    """Switch the shared console to write to stderr so stdout stays clean for JSON."""
    global console
    console = Console(file=sys.stderr)
    return console


def quiet_console():
    """Replace the shared console with a no-op quiet instance (suppresses all output)."""
    global console
    console = Console(quiet=True)
    return console


def create_progress():
    """Create a standard Progress bar used by both collectors."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
    )


def build_live_display(progress, status_lines, current=None):
    """Build a renderable group for Rich Live display."""
    parts = [progress]
    for line in status_lines:
        parts.append(line)
    if current:
        parts.append(current)
    return Group(*parts)
