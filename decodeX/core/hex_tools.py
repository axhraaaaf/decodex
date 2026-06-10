"""Hexadecimal encoding and decoding tools."""

from __future__ import annotations

import argparse
import string

from decodeX.utils import print_error, print_result, run_with_status

COMMAND_NAME = "hex"


def text_to_hex(text: str) -> str:
    """Encode UTF-8 text as a lowercase hexadecimal string."""
    return text.encode("utf-8").hex()


def hex_to_text(hex_string: str) -> str:
    """Decode a hexadecimal string into UTF-8 text.

    Whitespace is ignored so values like "48 65 6c 6c 6f" are accepted.
    Both uppercase and lowercase hex characters are valid.
    """
    normalized_hex = _normalize_hex(hex_string)

    try:
        decoded_bytes = bytes.fromhex(normalized_hex)
        return decoded_bytes.decode("utf-8")
    except ValueError as exc:
        raise ValueError("Invalid hex input.") from exc
    except UnicodeDecodeError as exc:
        raise ValueError("Decoded bytes are not valid UTF-8 text.") from exc


def register_subcommand(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register hex CLI commands."""
    parser = subparsers.add_parser(
        COMMAND_NAME,
        help="Encode and decode hexadecimal data.",
        description="Encode UTF-8 text to hex, and decode hex back to UTF-8 text.",
    )
    hex_subparsers = parser.add_subparsers(
        dest="hex_action",
        metavar="action",
        help="Hex actions.",
        required=True,
    )

    encode_parser = hex_subparsers.add_parser(
        "encode",
        help="Encode text to hex.",
        description="Encode UTF-8 text as lowercase hexadecimal.",
    )
    encode_parser.add_argument("text", help="UTF-8 text to encode.")
    encode_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON.",
    )
    encode_parser.set_defaults(handler=handle_encode_command)

    decode_parser = hex_subparsers.add_parser(
        "decode",
        help="Decode hex to text.",
        description="Decode hexadecimal input as UTF-8 text.",
    )
    decode_parser.add_argument(
        "hex_string",
        help="Hex input to decode. Whitespace is allowed between bytes.",
    )
    decode_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON.",
    )
    decode_parser.set_defaults(handler=handle_decode_command)


def handle_encode_command(args: argparse.Namespace) -> int:
    """Handle the hex encode command."""
    try:
        result = run_with_status(
            "Encoding UTF-8 text as hex...",
            lambda: text_to_hex(args.text),
        )
        if getattr(args, "json", False):
            import json
            print(json.dumps({"title": "Encoded text as hex", "result": result}, indent=2))
        else:
            print_result("Encoded text as hex", result, border_style="green")
        return 0
    except UnicodeEncodeError as exc:
        print_error(f"Hex encode error: {exc}")
        return 2


def handle_decode_command(args: argparse.Namespace) -> int:
    """Handle the hex decode command."""
    try:
        result = run_with_status(
            "Decoding hex as UTF-8 text...",
            lambda: hex_to_text(args.hex_string),
        )
        if getattr(args, "json", False):
            import json
            print(json.dumps({"title": "Decoded hex as UTF-8 text", "result": result}, indent=2))
        else:
            print_result("Decoded hex as UTF-8 text", result, border_style="cyan")
        return 0
    except ValueError as exc:
        print_error(f"Hex decode error: {exc}")
        return 2


def _normalize_hex(hex_string: str) -> str:
    """Remove whitespace and validate hex input before decoding."""
    normalized_hex = "".join(hex_string.split())

    # Validate before bytes.fromhex so CLI errors are clear and predictable.
    invalid_characters = sorted(
        {character for character in normalized_hex if character not in string.hexdigits}
    )
    if invalid_characters:
        invalid_list = ", ".join(repr(character) for character in invalid_characters)
        raise ValueError(
            "Invalid hex input: only hexadecimal characters and whitespace are "
            f"allowed. Found: {invalid_list}."
        )

    if len(normalized_hex) % 2 != 0:
        raise ValueError("Invalid hex input: expected an even number of hex digits.")

    return normalized_hex
