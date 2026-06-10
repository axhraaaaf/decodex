"""Strings extraction plugin."""

from pathlib import Path
from typing import Any

from decodeX.framework.plugin_base import Plugin

def extract_strings(data: bytes, *, min_length: int = 4) -> list[dict[str, Any]]:
    """Extract printable ASCII and UTF-16LE strings from bytes."""
    strings_found = _extract_ascii_strings(data, min_length=min_length)
    strings_found.extend(_extract_utf16le_strings(data, min_length=min_length))
    strings_found.sort(key=lambda extracted: extracted["offset"])
    return strings_found

def _extract_ascii_strings(data: bytes, *, min_length: int) -> list[dict[str, Any]]:
    """Extract printable ASCII strings."""
    results: list[dict[str, Any]] = []
    start: int | None = None
    buffer: list[str] = []

    for index, byte in enumerate(data):
        if 32 <= byte <= 126:
            if start is None:
                start = index
            buffer.append(chr(byte))
            continue

        if start is not None and len(buffer) >= min_length:
            results.append({"offset": start, "encoding": "ASCII", "value": "".join(buffer)})
        start = None
        buffer = []

    if start is not None and len(buffer) >= min_length:
        results.append({"offset": start, "encoding": "ASCII", "value": "".join(buffer)})

    return results

def _extract_utf16le_strings(data: bytes, *, min_length: int) -> list[dict[str, Any]]:
    """Extract simple UTF-16LE printable strings."""
    results: list[dict[str, Any]] = []
    index = 0

    while index + 1 < len(data):
        if 32 <= data[index] <= 126 and data[index + 1] == 0:
            start = index
            characters: list[str] = []
            while index + 1 < len(data) and 32 <= data[index] <= 126 and data[index + 1] == 0:
                characters.append(chr(data[index]))
                index += 2

            if len(characters) >= min_length:
                results.append({"offset": start, "encoding": "UTF-16LE", "value": "".join(characters)})
            continue

        index += 1

    return results

class StringsPlugin(Plugin):
    """Plugin to extract sequence of printable characters."""

    @property
    def name(self) -> str:
        return "strings"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Extracts printable ASCII and UTF-16LE strings."

    def analyze(self, target: Path | str | bytes, min_length: int = 4) -> dict[str, Any]:
        """Extract strings from the target file."""
        if isinstance(target, bytes):
            data = target
        else:
            path = Path(target)
            try:
                data = path.read_bytes()
            except OSError as exc:
                raise OSError(f"Could not read file '{path}': {exc.strerror}") from exc

        extracted = extract_strings(data, min_length=min_length)
        
        return {
            "count": len(extracted),
            "extracted": extracted,
        }
