"""Magic-byte file type detection."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from decodeX.utils import (
    print_error,
    print_info,
    print_key_value_table,
    run_with_status,
)

COMMAND_NAME = "file"
DETECT_ACTION = "detect"
UNKNOWN_FILE_TYPE = "Unknown"


@dataclass(frozen=True)
class MagicSignature:
    """Known magic-byte signatures for one file type."""

    file_type: str
    signatures: tuple[bytes, ...]


@dataclass(frozen=True)
class MagicDetection:
    """Result of analyzing a file header."""

    file_path: Path
    detected_type: str
    header: bytes
    matched_signature: bytes | None

    @property
    def is_known(self) -> bool:
        """Return whether a known file signature was found."""
        return self.detected_type != UNKNOWN_FILE_TYPE

    @property
    def header_hex(self) -> str:
        """Return analyzed header bytes as uppercase spaced hex."""
        return _format_bytes(self.header)

    @property
    def signature_hex(self) -> str:
        """Return matched signature bytes as uppercase spaced hex."""
        if self.matched_signature is None:
            return "N/A"
        return _format_bytes(self.matched_signature)


MAGIC_SIGNATURES: tuple[MagicSignature, ...] = (
    MagicSignature("PNG", (b"\x89PNG\r\n\x1a\n",)),
    MagicSignature("JPEG", (b"\xff\xd8\xff",)),
    MagicSignature("PDF", (b"%PDF-",)),
    MagicSignature("ZIP", (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")),
    MagicSignature("ELF", (b"\x7fELF",)),
    MagicSignature("EXE", (b"MZ",)),
    MagicSignature("GIF", (b"GIF87a", b"GIF89a")),
    MagicSignature("MP3", (b"ID3", b"\xff\xfb", b"\xff\xf3", b"\xff\xf2")),
)

MAX_SIGNATURE_LENGTH = max(
    len(signature)
    for magic_signature in MAGIC_SIGNATURES
    for signature in magic_signature.signatures
)


def register_subcommand(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register file analysis CLI commands."""
    parser = subparsers.add_parser(
        COMMAND_NAME,
        help="Analyze file metadata and headers.",
        description="Analyze file headers using known magic-byte signatures.",
    )
    file_subparsers = parser.add_subparsers(
        dest="file_action",
        metavar="action",
        help="File actions.",
        required=True,
    )

    detect_parser = file_subparsers.add_parser(
        DETECT_ACTION,
        help="Detect file type from magic bytes.",
        description="Detect common file types by inspecting the file header.",
    )
    detect_parser.add_argument("path", help="Path to the file to analyze.")
    detect_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON.",
    )
    detect_parser.set_defaults(handler=handle_detect_command)


def detect_magic_bytes(file_path: str | Path) -> str:
    """Detect a file type by reading and matching its magic bytes."""
    return analyze_magic_bytes(file_path).detected_type


def analyze_magic_bytes(file_path: str | Path) -> MagicDetection:
    """Analyze a file header and return detailed magic-byte information."""
    path = Path(file_path)
    try:
        header = _read_header(path)
    except OSError as exc:
        raise OSError(f"Could not read file '{path}': {exc.strerror}") from exc

    for magic_signature in MAGIC_SIGNATURES:
        for signature in magic_signature.signatures:
            if header.startswith(signature):
                return MagicDetection(
                    file_path=path,
                    detected_type=magic_signature.file_type,
                    header=header,
                    matched_signature=signature,
                )

    return MagicDetection(
        file_path=path,
        detected_type=UNKNOWN_FILE_TYPE,
        header=header,
        matched_signature=None,
    )


def handle_detect_command(args: argparse.Namespace) -> int:
    """Handle file magic-byte detection."""
    try:
        detection = run_with_status(
            "Reading file header and matching magic bytes...",
            lambda: analyze_magic_bytes(args.path),
        )
    except OSError as exc:
        print_error(f"File detect error: {exc}")
        return 2

    if getattr(args, "json", False):
        import json
        print(json.dumps({
            "path": str(detection.file_path),
            "detected_type": detection.detected_type,
            "matched_signature": detection.signature_hex,
            "header_analyzed": detection.header_hex,
            "is_known": detection.is_known
        }, indent=2))
    else:
        print_key_value_table(
            "Magic-byte file detection",
            (
                ("Path", str(detection.file_path)),
                ("Detected type", detection.detected_type),
                ("Matched signature", detection.signature_hex),
                ("Header analyzed", detection.header_hex),
            ),
        )

        if not detection.is_known:
            print_info("Unknown file type. No known signature matched safely.")

    return 0


def _read_header(path: Path) -> bytes:
    """Read enough bytes to compare all known signatures."""
    with path.open("rb") as file_handle:
        return file_handle.read(MAX_SIGNATURE_LENGTH)


def _format_bytes(data: bytes) -> str:
    """Format bytes as uppercase spaced hexadecimal for terminal output."""
    if not data:
        return "N/A"
    return " ".join(f"{byte:02X}" for byte in data)
