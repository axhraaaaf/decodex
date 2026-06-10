"""Base64 encoding and decoding tools."""

from __future__ import annotations

import argparse
import base64
import binascii
from pathlib import Path

from decodeX.utils import print_error, print_result, run_with_status

COMMAND_NAME = "base64"


def encode_base64(text: str) -> str:
    """Encode UTF-8 text as a Base64 string."""
    encoded_bytes = base64.b64encode(text.encode("utf-8"))
    return encoded_bytes.decode("ascii")


def decode_base64(text: str) -> str:
    """Decode a Base64 string into UTF-8 text."""
    try:
        decoded_bytes = base64.b64decode(text.encode("ascii"), validate=True)
        return decoded_bytes.decode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Base64 input must contain ASCII characters only.") from exc
    except binascii.Error as exc:
        raise ValueError("Invalid Base64 input.") from exc
    except UnicodeDecodeError as exc:
        raise ValueError("Decoded data is not valid UTF-8 text.") from exc


def encode_file_base64(path: str | Path) -> str:
    """Read a file as bytes and return its Base64 representation."""
    file_path = Path(path)
    try:
        encoded_bytes = base64.b64encode(file_path.read_bytes())
        return encoded_bytes.decode("ascii")
    except OSError as exc:
        raise OSError(f"Could not read file '{file_path}': {exc.strerror}") from exc


def decode_file_base64(path: str | Path) -> str:
    """Read Base64 data from a file and decode it into UTF-8 text."""
    file_path = Path(path)
    try:
        # Base64 files are often line-wrapped, so ignore whitespace around chunks.
        encoded_text = "".join(file_path.read_text(encoding="utf-8").split())
    except OSError as exc:
        raise OSError(f"Could not read file '{file_path}': {exc.strerror}") from exc

    return decode_base64(encoded_text)


def register_subcommand(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register Base64 CLI commands."""
    parser = subparsers.add_parser(
        COMMAND_NAME,
        help="Encode and decode Base64 data.",
        description="Encode UTF-8 text or files to Base64, and decode Base64 to text.",
    )
    base64_subparsers = parser.add_subparsers(
        dest="base64_action",
        metavar="action",
        help="Base64 actions.",
        required=True,
    )

    encode_parser = base64_subparsers.add_parser(
        "encode",
        help="Encode text or a file to Base64.",
        description="Encode UTF-8 text or raw file bytes to Base64.",
    )
    _add_input_arguments(encode_parser)
    encode_parser.set_defaults(handler=handle_encode_command)

    decode_parser = base64_subparsers.add_parser(
        "decode",
        help="Decode Base64 to UTF-8 text.",
        description="Decode Base64 text or Base64 data stored in a file.",
    )
    _add_input_arguments(decode_parser)
    decode_parser.set_defaults(handler=handle_decode_command)


def handle_encode_command(args: argparse.Namespace) -> int:
    """Handle the Base64 encode command."""
    try:
        if args.file:
            result = run_with_status(
                "Encoding file bytes as Base64...",
                lambda: encode_file_base64(args.value),
            )
            title = f"Encoded file '{args.value}' as Base64"
        else:
            result = run_with_status(
                "Encoding UTF-8 text as Base64...",
                lambda: encode_base64(args.value),
            )
            title = "Encoded text as Base64"

        if getattr(args, "json", False):
            import json
            print(json.dumps({"title": title, "result": result}, indent=2))
        else:
            print_result(title, result, border_style="green")
        return 0
    except (OSError, ValueError) as exc:
        print_error(f"Base64 encode error: {exc}")
        return 2


def handle_decode_command(args: argparse.Namespace) -> int:
    """Handle the Base64 decode command."""
    try:
        if args.file:
            result = run_with_status(
                "Decoding Base64 file as UTF-8 text...",
                lambda: decode_file_base64(args.value),
            )
            title = f"Decoded Base64 file '{args.value}' as UTF-8 text"
        else:
            result = run_with_status(
                "Decoding Base64 as UTF-8 text...",
                lambda: decode_base64(args.value),
            )
            title = "Decoded Base64 as UTF-8 text"

        if getattr(args, "json", False):
            import json
            print(json.dumps({"title": title, "result": result}, indent=2))
        else:
            print_result(title, result, border_style="cyan")
        return 0
    except (OSError, ValueError) as exc:
        print_error(f"Base64 decode error: {exc}")
        return 2


def _add_input_arguments(parser: argparse.ArgumentParser) -> None:
    """Add shared text/file input arguments to a Base64 action parser."""
    parser.add_argument(
        "value",
        help="Text value by default, or a file path when --file is used.",
    )
    parser.add_argument(
        "-f",
        "--file",
        action="store_true",
        help="Treat the value argument as a file path.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON.",
    )
