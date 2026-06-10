"""Automatic encoding and container signature detection."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import string
from dataclasses import dataclass
from urllib.parse import unquote_plus

from decodeX.utils import print_error, print_info, print_table, run_with_status

COMMAND_NAME = "detect"
GZIP_MAGIC = b"\x1f\x8b"
MIN_CONFIDENCE = 50


@dataclass(frozen=True)
class EncodingDetection:
    """A possible encoding match with confidence and recommended action."""

    encoding: str
    confidence: int
    evidence: str
    suggested_action: str


def detect_encodings(value: str) -> list[EncodingDetection]:
    """Detect likely encodings and signatures for a text input."""
    if not value:
        raise ValueError("Input cannot be empty.")

    candidates = [
        _detect_jwt(value),
        _detect_base64(value),
        _detect_hex(value),
        _detect_binary(value),
        _detect_url_encoding(value),
        _detect_gzip_signature(value),
    ]
    detections = [
        detection
        for detection in candidates
        if detection is not None and detection.confidence >= MIN_CONFIDENCE
    ]
    detections.sort(key=lambda detection: detection.confidence, reverse=True)

    return _deduplicate_detections(detections)


def register_subcommand(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    """Register automatic encoding detection CLI command."""
    parser = subparsers.add_parser(
        COMMAND_NAME,
        help="Detect likely encodings and signatures.",
        description="Detect Base64, hex, binary, URL encoding, JWTs, and gzip signatures.",
    )
    parser.add_argument("value", help="Text or encoded value to inspect.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON.",
    )
    parser.set_defaults(handler=handle_detect_command)


def handle_detect_command(args: argparse.Namespace) -> int:
    """Handle automatic encoding detection."""
    try:
        detections = run_with_status(
            "Running encoding heuristics...",
            lambda: detect_encodings(args.value),
        )
    except ValueError as exc:
        print_error(f"Detect error: {exc}")
        return 2

    if getattr(args, "json", False):
        import json
        results = []
        for d in detections:
            results.append({
                "encoding": d.encoding,
                "confidence": d.confidence,
                "evidence": d.evidence,
                "suggested_action": d.suggested_action
            })
        print(json.dumps({"title": "Automatic encoding detection", "results": results}, indent=2))
    elif not detections:
        print_info("No strong encoding match found. Treat input as unknown/plain text.")
        return 0
    else:
        _print_detection_results(detections)
    return 0


def _detect_base64(value: str) -> EncodingDetection | None:
    """Detect standard Base64 text."""
    normalized = "".join(value.split())
    if len(normalized) < 4 or not _uses_base64_alphabet(normalized):
        return None

    padded = _pad_base64(normalized)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None

    if not decoded:
        return None

    confidence = 60
    evidence = "Valid Base64 alphabet and decodable payload."

    if len(normalized) % 4 == 0:
        confidence += 10
    if value.endswith("="):
        confidence += 10
    if _looks_like_text(decoded):
        confidence += 15
        evidence = "Decodes cleanly to readable text."
    if decoded.startswith(GZIP_MAGIC):
        confidence += 10
        evidence = "Base64 payload decodes to gzip magic bytes."
    if _looks_like_binary_digits(normalized):
        confidence -= 35
        evidence = "Decodable as Base64, but input looks more like binary digits."
    elif _looks_like_hex_digits(normalized):
        confidence -= 25
        evidence = "Decodable as Base64, but input looks more like hex."

    return EncodingDetection(
        "Base64",
        min(confidence, 99),
        evidence,
        "Decode with: decodex base64 decode <value>",
    )


def _detect_hex(value: str) -> EncodingDetection | None:
    """Detect hexadecimal text."""
    normalized = "".join(value.split())
    if len(normalized) < 2:
        return None
    if len(normalized) % 2 != 0:
        return None
    if any(character not in string.hexdigits for character in normalized):
        return None

    try:
        decoded = bytes.fromhex(normalized)
    except ValueError:
        return None

    confidence = 65
    evidence = "Even-length hexadecimal alphabet."
    if " " in value.strip():
        confidence += 5
        evidence = "Spaced even-length hexadecimal bytes."
    if _looks_like_text(decoded):
        confidence += 15
        evidence = "Hex decodes to readable UTF-8 text."
    if decoded.startswith(GZIP_MAGIC):
        confidence += 15
        evidence = "Hex decodes to gzip magic bytes."
    if _looks_like_binary_digits(normalized):
        confidence -= 30
        evidence = "Valid hex digits, but input looks more like binary."

    return EncodingDetection(
        "Hex",
        min(confidence, 98),
        evidence,
        "Decode with: decodex hex decode <value>",
    )


def _detect_binary(value: str) -> EncodingDetection | None:
    """Detect binary strings made of 0 and 1."""
    normalized = "".join(value.split())
    if len(normalized) < 8 or set(normalized) - {"0", "1"}:
        return None

    confidence = 65
    evidence = "Input contains only binary digits."
    if len(normalized) % 8 == 0:
        confidence += 20
        evidence = "Binary length aligns to full bytes."
        decoded = _binary_to_bytes(normalized)
        if decoded is not None and _looks_like_text(decoded):
            confidence += 10
            evidence = "Binary bytes decode to readable text."

    return EncodingDetection(
        "Binary",
        min(confidence, 98),
        evidence,
        "Decode bits into bytes, then inspect as text or hex.",
    )


def _detect_url_encoding(value: str) -> EncodingDetection | None:
    """Detect percent or form-style URL encoding."""
    percent_matches = re.findall(r"%[0-9A-Fa-f]{2}", value)
    has_plus = "+" in value
    decoded = unquote_plus(value)

    if not percent_matches and not has_plus:
        return None
    if decoded == value:
        return None

    confidence = 60 + min(len(percent_matches) * 8, 30)
    evidence = "Contains percent-encoded byte sequences."
    if has_plus:
        confidence += 5
        evidence = "Contains URL/form encoding markers."

    return EncodingDetection(
        "URL encoding",
        min(confidence, 96),
        evidence,
        "Decode with URL percent-decoding, then re-run decodex detect.",
    )


def _detect_jwt(value: str) -> EncodingDetection | None:
    """Detect JSON Web Tokens."""
    parts = value.split(".")
    if len(parts) != 3 or any(not part for part in parts[:2]):
        return None
    if any(not _uses_base64url_alphabet(part) for part in parts):
        return None

    try:
        header = _decode_base64url_json(parts[0])
        payload = _decode_base64url_json(parts[1])
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None

    confidence = 85
    evidence = "Three Base64URL sections with JSON header and payload."
    if "alg" in header:
        confidence += 8
    if "typ" in header and str(header["typ"]).upper() == "JWT":
        confidence += 5

    claims = ", ".join(sorted(str(key) for key in payload.keys())[:4])
    if claims:
        evidence = f"Valid JWT structure. Payload claims include: {claims}."

    return EncodingDetection(
        "JWT",
        min(confidence, 99),
        evidence,
        "Decode header/payload with Base64URL; verify signature before trusting claims.",
    )


def _detect_gzip_signature(value: str) -> EncodingDetection | None:
    """Detect gzip magic bytes in raw, hex, or Base64-looking input."""
    byte_sources = _candidate_byte_sources(value)

    for source_name, data in byte_sources:
        if data.startswith(GZIP_MAGIC):
            confidence = 98 if source_name == "raw" else 92
            return EncodingDetection(
                "Gzip signature",
                confidence,
                f"Gzip magic bytes found in {source_name} input.",
                "Decompress with gzip tooling after converting to bytes.",
            )

    return None


def _candidate_byte_sources(value: str) -> list[tuple[str, bytes]]:
    """Build byte interpretations used by signature heuristics."""
    sources = [("raw", value.encode("latin-1", errors="ignore"))]
    normalized = "".join(value.split())

    if normalized and len(normalized) % 2 == 0:
        try:
            sources.append(("hex-decoded", bytes.fromhex(normalized)))
        except ValueError:
            pass

    if normalized and _uses_base64_alphabet(normalized):
        try:
            sources.append(("base64-decoded", base64.b64decode(_pad_base64(normalized))))
        except (binascii.Error, ValueError):
            pass

    return sources


def _decode_base64url_json(value: str) -> dict[str, object]:
    """Decode a Base64URL JWT section as JSON."""
    decoded = base64.urlsafe_b64decode(_pad_base64(value))
    result = json.loads(decoded.decode("utf-8"))
    if not isinstance(result, dict):
        raise ValueError("JWT section is not a JSON object.")
    return result


def _binary_to_bytes(value: str) -> bytes | None:
    """Convert byte-aligned binary text to bytes."""
    if len(value) % 8 != 0:
        return None
    return bytes(int(value[index : index + 8], 2) for index in range(0, len(value), 8))


def _looks_like_text(data: bytes) -> bool:
    """Return whether decoded bytes look like readable terminal text."""
    if not data:
        return False

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False

    readable = sum(
        character in string.printable and character not in "\x0b\x0c"
        for character in text
    )
    return readable / len(text) >= 0.85


def _uses_base64_alphabet(value: str) -> bool:
    """Return whether a value uses the standard Base64 alphabet."""
    return bool(re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", value))


def _uses_base64url_alphabet(value: str) -> bool:
    """Return whether a value uses the Base64URL alphabet."""
    return bool(re.fullmatch(r"[A-Za-z0-9_-]*", value))


def _looks_like_binary_digits(value: str) -> bool:
    """Return whether text is more plausibly binary than Base64."""
    return len(value) >= 8 and len(value) % 8 == 0 and set(value) <= {"0", "1"}


def _looks_like_hex_digits(value: str) -> bool:
    """Return whether text is more plausibly hex than Base64."""
    return (
        len(value) >= 4
        and len(value) % 2 == 0
        and all(character in string.hexdigits for character in value)
    )


def _pad_base64(value: str) -> str:
    """Add missing Base64 padding for heuristic decoding."""
    return value + ("=" * (-len(value) % 4))


def _deduplicate_detections(
    detections: list[EncodingDetection],
) -> list[EncodingDetection]:
    """Keep the strongest detection per encoding label."""
    strongest: dict[str, EncodingDetection] = {}
    for detection in detections:
        current = strongest.get(detection.encoding)
        if current is None or detection.confidence > current.confidence:
            strongest[detection.encoding] = detection

    return sorted(strongest.values(), key=lambda detection: detection.confidence, reverse=True)


def _print_detection_results(detections: list[EncodingDetection]) -> None:
    """Print formatted detection results."""
    rows = [
        (
            detection.encoding,
            f"{detection.confidence}%",
            detection.evidence,
            detection.suggested_action,
        )
        for detection in detections
    ]
    print_table(
        "Automatic encoding detection",
        (
            ("Encoding", "bold cyan"),
            ("Confidence", "bold green"),
            ("Evidence", "white"),
            ("Suggested action", "yellow"),
        ),
        rows,
    )
