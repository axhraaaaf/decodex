"""XOR encryption, decryption, and brute-force helpers."""

from __future__ import annotations

import argparse
import string
from dataclasses import dataclass

from decodeX.utils import (
    print_error,
    print_key_value_table,
    print_result,
    print_table,
    run_with_status,
)

COMMAND_NAME = "xor"
DEFAULT_BRUTE_FORCE_RESULTS = 10


@dataclass(frozen=True)
class XorCandidate:
    """A likely plaintext candidate from single-byte XOR brute forcing."""

    key: int
    plaintext: bytes
    score: float
    readable: bool

    @property
    def key_hex(self) -> str:
        """Return the candidate key as two-digit hexadecimal."""
        return f"{self.key:02x}"

    @property
    def key_display(self) -> str:
        """Return a terminal-safe printable key representation."""
        character = chr(self.key)
        if character in string.printable and character not in "\r\n\t\x0b\x0c":
            return repr(character)
        return "."

    @property
    def preview(self) -> str:
        """Return a terminal-safe plaintext preview."""
        return _bytes_to_terminal_text(self.plaintext)


def xor_encrypt(data: str | bytes, key: str | bytes) -> bytes:
    """XOR data with a repeating key and return encrypted bytes."""
    data_bytes = _coerce_to_bytes(data, "data")
    key_bytes = _coerce_to_bytes(key, "key")
    _validate_key(key_bytes)

    return bytes(
        value ^ key_bytes[index % len(key_bytes)]
        for index, value in enumerate(data_bytes)
    )


def xor_decrypt(data: str | bytes, key: str | bytes) -> bytes:
    """XOR encrypted data with a repeating key and return decrypted bytes."""
    return xor_encrypt(data, key)


def brute_force_single_byte_xor(
    ciphertext: str | bytes,
    top_results: int = DEFAULT_BRUTE_FORCE_RESULTS,
) -> list[XorCandidate]:
    """Return top likely plaintexts for a single-byte XOR hex ciphertext."""
    ciphertext_bytes = _coerce_ciphertext_to_bytes(ciphertext)
    if not ciphertext_bytes:
        raise ValueError("Ciphertext cannot be empty.")
    if top_results < 1:
        raise ValueError("top_results must be at least 1.")

    candidates = [
        _build_candidate(key, ciphertext_bytes)
        for key in range(256)
    ]
    candidates.sort(key=lambda candidate: candidate.score, reverse=True)
    return candidates[:top_results]


def _add_json_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON.",
    )

def register_subcommand(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register XOR CLI commands."""
    parser = subparsers.add_parser(
        COMMAND_NAME,
        help="Encrypt, decrypt, and brute-force XOR data.",
        description="Work with repeating-key XOR and single-byte XOR brute forcing.",
    )
    xor_subparsers = parser.add_subparsers(
        dest="xor_action",
        metavar="action",
        help="XOR actions.",
        required=True,
    )

    encrypt_parser = xor_subparsers.add_parser(
        "encrypt",
        help="Encrypt text with a repeating XOR key.",
        description="Encrypt UTF-8 text with a repeating XOR key and print hex output.",
    )
    encrypt_parser.add_argument("text", help="UTF-8 text to encrypt.")
    encrypt_parser.add_argument("key", help="UTF-8 XOR key.")
    _add_json_arg(encrypt_parser)
    encrypt_parser.set_defaults(handler=handle_encrypt_command)

    decrypt_parser = xor_subparsers.add_parser(
        "decrypt",
        help="Decrypt hex data with a repeating XOR key.",
        description="Decrypt hex-encoded XOR ciphertext with a repeating UTF-8 key.",
    )
    decrypt_parser.add_argument(
        "ciphertext",
        help="Hex ciphertext to decrypt. Whitespace is allowed between bytes.",
    )
    decrypt_parser.add_argument("key", help="UTF-8 XOR key.")
    _add_json_arg(decrypt_parser)
    decrypt_parser.set_defaults(handler=handle_decrypt_command)

    brute_parser = xor_subparsers.add_parser(
        "brute",
        help="Brute-force single-byte XOR ciphertext.",
        description="Score all single-byte XOR keys and print the top candidates.",
    )
    brute_parser.add_argument(
        "ciphertext",
        help="Hex ciphertext to brute-force. Whitespace is allowed between bytes.",
    )
    brute_parser.add_argument(
        "-n",
        "--top",
        type=int,
        default=DEFAULT_BRUTE_FORCE_RESULTS,
        help=f"Number of top candidates to show (default: {DEFAULT_BRUTE_FORCE_RESULTS}).",
    )
    _add_json_arg(brute_parser)
    brute_parser.set_defaults(handler=handle_brute_command)


def handle_encrypt_command(args: argparse.Namespace) -> int:
    """Handle the XOR encrypt command."""
    try:
        ciphertext = run_with_status(
            "Applying repeating-key XOR encryption...",
            lambda: xor_encrypt(args.text, args.key),
        )
        if getattr(args, "json", False):
            import json
            print(json.dumps({"title": "XOR encrypted hex", "result": ciphertext.hex()}, indent=2))
        else:
            print_result("XOR encrypted hex", ciphertext.hex(), border_style="green")
        return 0
    except ValueError as exc:
        print_error(f"XOR encrypt error: {exc}")
        return 2


def handle_decrypt_command(args: argparse.Namespace) -> int:
    """Handle the XOR decrypt command."""
    try:
        plaintext = run_with_status(
            "Applying repeating-key XOR decryption...",
            lambda: xor_decrypt(_hex_to_bytes(args.ciphertext), args.key),
        )
        if getattr(args, "json", False):
            import json
            print(json.dumps({
                "title": "XOR decrypted text",
                "result": _bytes_to_terminal_text(plaintext),
                "plaintext_hex": plaintext.hex()
            }, indent=2))
        else:
            print_result(
                "XOR decrypted text",
                _bytes_to_terminal_text(plaintext),
                border_style="cyan",
            )
            print_key_value_table(
                "Plaintext details",
                (("Plaintext hex", plaintext.hex()),),
            )
        return 0
    except ValueError as exc:
        print_error(f"XOR decrypt error: {exc}")
        return 2


def handle_brute_command(args: argparse.Namespace) -> int:
    """Handle the single-byte XOR brute-force command."""
    try:
        candidates = run_with_status(
            "Scoring single-byte XOR keyspace...",
            lambda: brute_force_single_byte_xor(args.ciphertext, args.top),
        )
        if getattr(args, "json", False):
            import json
            results = []
            for c in candidates:
                results.append({
                    "key_hex": f"0x{c.key_hex}",
                    "key_display": c.key_display,
                    "score": round(c.score, 2),
                    "readable": c.readable,
                    "preview": c.preview
                })
            print(json.dumps({"title": "Top single-byte XOR candidates", "results": results}, indent=2))
        else:
            _print_brute_force_results(candidates)
        return 0
    except ValueError as exc:
        print_error(f"XOR brute-force error: {exc}")
        return 2


def _build_candidate(key: int, ciphertext: bytes) -> XorCandidate:
    """Build a scored candidate for one single-byte XOR key."""
    key_bytes = bytes([key])
    plaintext = xor_decrypt(ciphertext, key_bytes)
    score = _score_english_plaintext(plaintext)
    return XorCandidate(
        key=key,
        plaintext=plaintext,
        score=score,
        readable=_is_readable_plaintext(plaintext),
    )


def _score_english_plaintext(data: bytes) -> float:
    """Score bytes by how likely they are to be readable English text."""
    if not data:
        return float("-inf")

    score = 0.0
    text = data.decode("utf-8", errors="replace")
    lowercase_text = text.lower()
    common_letters = "etaoinshrdlu"
    common_words = (" the ", " and ", " of ", " to ", " in ", " is ", " that ")

    for byte in data:
        character = chr(byte)
        if character in string.ascii_letters:
            score += 2.0
            if character.lower() in common_letters:
                score += 1.0
        elif character == " ":
            score += 3.0
        elif character in string.digits:
            score += 0.8
        elif character in ".,;:'\"!?()-_/":
            score += 0.5
        elif character in "\r\n\t":
            score += 0.1
        elif byte < 32 or byte == 127:
            score -= 6.0
        else:
            score -= 1.5

    score += sum(lowercase_text.count(word) * 5.0 for word in common_words)

    # Normalizing keeps scores comparable across short and long ciphertexts.
    normalized_score = score / len(data)
    if _is_readable_plaintext(data):
        normalized_score += 2.0
    return normalized_score


def _is_readable_plaintext(data: bytes) -> bool:
    """Return whether most bytes look safe and readable in a terminal."""
    if not data:
        return False

    readable_bytes = 0
    for byte in data:
        character = chr(byte)
        if character in string.printable and character not in "\x0b\x0c":
            readable_bytes += 1

    return readable_bytes / len(data) >= 0.85


def _coerce_to_bytes(value: str | bytes, label: str) -> bytes:
    """Convert text or bytes to bytes for XOR operations."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"{label} must be text or bytes.")


def _coerce_ciphertext_to_bytes(ciphertext: str | bytes) -> bytes:
    """Treat string ciphertext as hex and byte ciphertext as raw bytes."""
    if isinstance(ciphertext, bytes):
        return ciphertext
    if isinstance(ciphertext, str):
        return _hex_to_bytes(ciphertext)
    raise TypeError("ciphertext must be a hex string or bytes.")


def _validate_key(key: bytes) -> None:
    """Validate XOR key bytes."""
    if not key:
        raise ValueError("XOR key cannot be empty.")


def _hex_to_bytes(hex_string: str) -> bytes:
    """Decode hex with whitespace support and helpful validation."""
    normalized_hex = "".join(hex_string.split())
    if not normalized_hex:
        raise ValueError("Hex ciphertext cannot be empty.")

    invalid_characters = sorted(
        {character for character in normalized_hex if character not in string.hexdigits}
    )
    if invalid_characters:
        invalid_list = ", ".join(repr(character) for character in invalid_characters)
        raise ValueError(
            "Invalid hex ciphertext: only hexadecimal characters and whitespace are "
            f"allowed. Found: {invalid_list}."
        )

    if len(normalized_hex) % 2 != 0:
        raise ValueError("Invalid hex ciphertext: expected an even number of digits.")

    return bytes.fromhex(normalized_hex)


def _bytes_to_terminal_text(data: bytes) -> str:
    """Decode bytes and escape control characters for clean terminal output."""
    text = data.decode("utf-8", errors="backslashreplace")
    return text.encode("unicode_escape").decode("ascii")


def _print_brute_force_results(candidates: list[XorCandidate]) -> None:
    """Print brute-force candidates in a Rich table."""
    rows = []
    for rank, candidate in enumerate(candidates, start=1):
        readable = "[green]yes[/]" if candidate.readable else "[red]no[/]"
        rows.append(
            (
                str(rank),
                f"{candidate.score:.2f}",
                f"0x{candidate.key_hex}",
                candidate.key_display,
                readable,
                candidate.preview,
            )
        )

    print_table(
        "Top single-byte XOR candidates",
        (
            ("Rank", "bold"),
            ("Score", "cyan"),
            ("Key(hex)", "magenta"),
            ("Key", "yellow"),
            ("Readable", "green"),
            ("Plaintext", "white"),
        ),
        rows,
    )
