"""Command-line entry point for decodeX."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from decodeX import __app_name__, __version__
from decodeX.core import (
    analyze_tools,
    base64_tools,
    detect_tools,
    entropy_tools,
    hex_tools,
    magic_bytes,
    xor_tools,
)
from decodeX.framework.cli import register_framework_commands
from decodeX.utils import CommandHandler, DecodeXArgumentParser, print_error
from decodeX.utils.console import EXAMPLES_TEXT, print_banner

COMMAND_REGISTRARS = (
    base64_tools.register_subcommand,
    hex_tools.register_subcommand,
    xor_tools.register_subcommand,
    entropy_tools.register_subcommand,
    magic_bytes.register_subcommand,
    detect_tools.register_subcommand,
    register_framework_commands,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level CLI parser."""
    parser = DecodeXArgumentParser(
        prog="decodex",
        description="decodeX: Cybersecurity toolkit for CTFs and decoding Developped by Axhraaaaf",
        epilog=EXAMPLES_TEXT,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{__app_name__} {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        metavar="command",
        help="Available command groups.",
        parser_class=DecodeXArgumentParser,
    )

    # Each core module owns its CLI surface and will add real options later.
    for register_subcommand in COMMAND_REGISTRARS:
        register_subcommand(subparsers)

    return parser


def run(argv: Sequence[str] | None = None) -> int:
    """Parse command-line arguments and execute the selected handler."""
    parser = build_parser()
    args = parser.parse_args(argv)

    handler = getattr(args, "handler", None)

    if handler is None:
        parser.print_help()
        return 0

    try:
        return _call_handler(handler, args)
    except NotImplementedError as exc:
        print_error(f"Error: {exc}")
        return 2
    except Exception as exc:  # pragma: no cover - defensive CLI boundary.
        print_error(f"Unexpected error: {exc}")
        return 1


def _call_handler(handler: CommandHandler, args: argparse.Namespace) -> int:
    """Call a command handler through a typed boundary."""
    return handler(args)


def main() -> None:
    """Process exit wrapper for console execution."""
    raise SystemExit(run())


if __name__ == "__main__":
    main()
