"""Shared Rich display helpers."""

from rich.console import Console, Group
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

console = Console()


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
