"""Shannon entropy analysis for strings and files."""

from __future__ import annotations

import argparse
import math
from collections import Counter
from pathlib import Path

from decodeX.utils import (
    print_error,
    print_key_value_table,
    run_with_status,
    style_entropy_level,
)

COMMAND_NAME = "entropy"
FILE_COMMAND_NAME = "entropy-file"

LOW_ENTROPY_THRESHOLD = 3.5
HIGH_ENTROPY_THRESHOLD = 6.5


def calculate_shannon_entropy(data: str | bytes) -> float:
    """Calculate Shannon entropy in bits per byte."""
    data_bytes = _coerce_to_bytes(data)
    if not data_bytes:
        raise ValueError("Cannot calculate entropy for empty input.")

    frequencies = Counter(data_bytes)
    data_length = len(data_bytes)

    return -sum(
        (count / data_length) * math.log2(count / data_length)
        for count in frequencies.values()
    )


def analyze_string_entropy(text: str) -> tuple[float, str]:
    """Return entropy score and level for UTF-8 text."""
    entropy = calculate_shannon_entropy(text)
    return entropy, explain_entropy_level(entropy)


def analyze_file_entropy(path: str | Path) -> tuple[float, str, int]:
    """Return entropy score, level, and byte length for a file."""
    file_path = Path(path)
    try:
        data = file_path.read_bytes()
    except OSError as exc:
        raise OSError(f"Could not read file '{file_path}': {exc.strerror}") from exc

    entropy = calculate_shannon_entropy(data)
    return entropy, explain_entropy_level(entropy), len(data)


def explain_entropy_level(entropy: float) -> str:
    """Classify an entropy score as low, medium, or high."""
    if entropy < LOW_ENTROPY_THRESHOLD:
        return "low"
    if entropy < HIGH_ENTROPY_THRESHOLD:
        return "medium"
    return "high"


def register_subcommand(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register entropy CLI commands."""
    parser = subparsers.add_parser(
        COMMAND_NAME,
        help="Calculate Shannon entropy for text.",
        description="Analyze UTF-8 text and classify its Shannon entropy level.",
    )
    parser.add_argument("text", help="UTF-8 text to analyze.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON.",
    )
    parser.set_defaults(handler=handle_string_command)

    file_parser = subparsers.add_parser(
        FILE_COMMAND_NAME,
        help="Calculate Shannon entropy for a file.",
        description="Analyze file bytes and classify their Shannon entropy level.",
    )
    file_parser.add_argument("path", help="Path to the file to analyze.")
    file_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON.",
    )
    file_parser.set_defaults(handler=handle_file_command)


def handle_string_command(args: argparse.Namespace) -> int:
    """Handle text entropy analysis."""
    from decodeX.plugins.entropy_plugin import EntropyPlugin
    try:
        plugin = EntropyPlugin()
        # Analyze expects path or bytes for text.
        text_bytes = args.text.encode("utf-8")
        
        def _analyze_string() -> tuple[float, str]:
            res = plugin.analyze(text_bytes)
            return res["score"], res["level"]

        entropy, level = run_with_status(
            "Calculating Shannon entropy...",
            _analyze_string,
        )
        if getattr(args, "json", False):
            import json
            print(json.dumps({
                "title": "Shannon entropy analysis",
                "input_type": "text",
                "bytes_analyzed": len(text_bytes),
                "entropy_score": round(entropy, 4),
                "entropy_level": level
            }, indent=2))
        else:
            print_key_value_table(
                "Shannon entropy analysis",
                (
                    ("Input type", "text"),
                    ("Bytes analyzed", str(len(text_bytes))),
                    ("Entropy score", f"{entropy:.4f} bits/byte"),
                    ("Entropy level", style_entropy_level(level)),
                ),
            )
        return 0
    except ValueError as exc:
        print_error(f"Entropy error: {exc}")
        return 2


def handle_file_command(args: argparse.Namespace) -> int:
    """Handle file entropy analysis."""
    from decodeX.plugins.entropy_plugin import EntropyPlugin
    try:
        plugin = EntropyPlugin()
        
        def _analyze_file() -> tuple[float, str, int]:
            # For bytes analyzed count, we can do a quick stat or just read it.
            # But the plugin doesn't return file size!
            # Since existing functionality printed bytes analyzed,
            # we should get it.
            path = Path(args.path)
            res = plugin.analyze(path)
            return res["score"], res["level"], path.stat().st_size

        entropy, level, byte_count = run_with_status(
            "Reading file and calculating Shannon entropy...",
            _analyze_file,
        )
        if getattr(args, "json", False):
            import json
            print(json.dumps({
                "title": "Shannon entropy analysis",
                "input_type": "file",
                "path": str(args.path),
                "bytes_analyzed": byte_count,
                "entropy_score": round(entropy, 4),
                "entropy_level": level
            }, indent=2))
        else:
            print_key_value_table(
                "Shannon entropy analysis",
                (
                    ("Input type", "file"),
                    ("Path", str(args.path)),
                    ("Bytes analyzed", str(byte_count)),
                    ("Entropy score", f"{entropy:.4f} bits/byte"),
                    ("Entropy level", style_entropy_level(level)),
                ),
            )
        return 0
    except (OSError, ValueError) as exc:
        print_error(f"Entropy file error: {exc}")
        return 2


def _coerce_to_bytes(data: str | bytes) -> bytes:
    """Convert supported entropy inputs to bytes."""
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8")
    raise TypeError("Entropy input must be text or bytes.")

