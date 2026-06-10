"""Terminal UI helpers for decodeX."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable, Iterable, Sequence
from typing import Any, TypeVar

try:
    import pyfiglet
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only before dependencies install.
    pyfiglet = None
    Console = None  # type: ignore[assignment]
    Panel = None  # type: ignore[assignment]
    Table = None  # type: ignore[assignment]
    Text = None  # type: ignore[assignment]
    RICH_AVAILABLE = False

T = TypeVar("T")

APP_TAGLINE = "Cybersecurity toolkit for CTFs and malware analysis"
SUCCESS_ICON = "[+]"
ERROR_ICON = "[!]"
INFO_ICON = "[*]"

EXAMPLES_TEXT = """Examples:
  decodex analyze suspicious.exe
  decodex base64 encode "hello"
  decodex base64 decode "SGVsbG8="
  decodex hex encode "hello"
  decodex hex decode "48 65 6c 6c 6f"
  decodex xor encrypt "hello" secret
  decodex xor brute "3b121b0a"
  decodex entropy "hello"
  decodex entropy-file malware.exe
  decodex file detect sample.bin
  decodex detect "SGVsbG8="
"""

if RICH_AVAILABLE:
    console = Console()
    error_console = Console(stderr=True)
else:
    console = None
    error_console = None


class DecodeXArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that renders help through the decodeX UI layer."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("formatter_class", argparse.RawDescriptionHelpFormatter)
        super().__init__(*args, **kwargs)

    def print_help(self, file: Any | None = None) -> None:
        """Print a banner and formatted help menu."""
        help_text = self.format_help()
        if file not in (None, sys.stdout):
            file.write(help_text)
            return

        print_banner()
        print_help_panel(help_text)

    def error(self, message: str) -> None:
        """Render argparse validation failures with decodeX error styling."""
        self.print_usage(sys.stderr)
        print_error(f"{self.prog}: {message}")
        raise SystemExit(2)


def print_banner() -> None:
    """Render the decodeX banner."""
    banner = _build_banner_text()
    if RICH_AVAILABLE:
        console.print(
            Panel.fit(
                Text(banner, style="bold cyan"),
                title="[bold green]decodeX[/bold green]",
                subtitle=f"[dim]{APP_TAGLINE}[/dim]",
                border_style="cyan",
            )
        )
        return

    print(banner)
    print(APP_TAGLINE)


def print_help_panel(help_text: str) -> None:
    """Render argparse help in a readable panel."""
    if RICH_AVAILABLE:
        console.print(
            Panel(
                help_text.rstrip(),
                title="[bold cyan]Help Menu[/bold cyan]",
                border_style="cyan",
            )
        )
        return

    print(help_text)


def print_success(message: str) -> None:
    """Print a successful operation message."""
    if RICH_AVAILABLE:
        console.print(f"[bold green]{SUCCESS_ICON}[/bold green] {message}")
        return

    print(f"{SUCCESS_ICON} {message}")


def print_error(message: str) -> None:
    """Print an error message."""
    if RICH_AVAILABLE:
        error_console.print(f"[bold red]{ERROR_ICON}[/bold red] [red]{message}[/red]")
        return

    print(f"{ERROR_ICON} {message}", file=sys.stderr)


def print_info(message: str) -> None:
    """Print an informational message."""
    if RICH_AVAILABLE:
        console.print(f"[bold blue]{INFO_ICON}[/bold blue] {message}")
        return

    print(f"{INFO_ICON} {message}")


def print_result(title: str, value: str, *, border_style: str = "green") -> None:
    """Print a single command result in a professional output panel."""
    print_success(title)
    if RICH_AVAILABLE:
        console.print(
            Panel(
                str(value),
                title="[bold]Output[/bold]",
                border_style=border_style,
                expand=False,
            )
        )
        return

    print(value)


def print_key_value_table(title: str, rows: Sequence[tuple[str, str]]) -> None:
    """Print key-value analysis details."""
    if RICH_AVAILABLE:
        table = Table(title=title, border_style="cyan", show_header=False)
        table.add_column("Field", style="bold cyan", no_wrap=True)
        table.add_column("Value", style="white", overflow="fold")
        for key, value in rows:
            table.add_row(key, value)
        console.print(table)
        return

    print(title)
    for key, value in rows:
        print(f"{key}: {value}")


def print_table(
    title: str,
    columns: Sequence[tuple[str, str]],
    rows: Iterable[Sequence[str]],
) -> None:
    """Print a styled table with a plain-text fallback."""
    if RICH_AVAILABLE:
        table = Table(title=title, border_style="cyan", header_style="bold cyan")
        for column_name, style in columns:
            table.add_column(column_name, style=style, overflow="fold")
        for row in rows:
            table.add_row(*row)
        console.print(table)
        return

    plain_rows = [
        tuple(_strip_markup(value) for value in row)
        for row in rows
    ]
    headers = [_strip_markup(column_name) for column_name, _style in columns]
    widths = []
    for index, header in enumerate(headers):
        row_widths = [len(row[index]) for row in plain_rows]
        widths.append(max([len(header), *row_widths]))
    print(title)
    print("  ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("  ".join("-" * width for width in widths))
    for row in plain_rows:
        print("  ".join(value.ljust(widths[index]) for index, value in enumerate(row)))


def run_with_status(message: str, callback: Callable[[], T]) -> T:
    """Run a short task under a Rich progress/status indicator, unless JSON output is requested."""
    is_json = "--json" in sys.argv or "--json-stdout" in sys.argv
    if RICH_AVAILABLE and not is_json:
        with console.status(f"[cyan]{message}[/cyan]", spinner="dots"):
            return callback()

    if not is_json:
        print_info(message)
    return callback()


def style_entropy_level(level: str) -> str:
    """Return a Rich-styled entropy label."""
    if not RICH_AVAILABLE:
        return level

    styles = {
        "low": "bold green",
        "medium": "bold yellow",
        "high": "bold red",
    }
    return f"[{styles[level]}]{level}[/]"


def _strip_markup(value: str) -> str:
    """Remove simple Rich markup tags for plain fallback output."""
    return re.sub(r"\[[^\]]*\]", "", value)


def _build_banner_text() -> str:
    """Build the custom decodeX ASCII banner."""
    return r"""
     █████                                █████          █████ █████
    ░░███                                ░░███          ░░███ ░░███ 
  ███████   ██████   ██████   ██████   ███████   ██████  ░░███ ███  
 ███░░███  ███░░███ ███░░███ ███░░███ ███░░███  ███░░███  ░░█████   
░███ ░███ ░███████ ░███ ░░░ ░███ ░███░███ ░███ ░███████    ███░███  
░███ ░███ ░███░░░  ░███  ███░███ ░███░███ ░███ ░███░░░    ███ ░░███ 
░░████████░░██████ ░░██████ ░░██████ ░░████████░░██████  █████ █████
 ░░░░░░░░  ░░░░░░   ░░░░░░   ░░░░░░   ░░░░░░░░  ░░░░░░  ░░░░░ ░░░░░ 
    """.strip("\n")
