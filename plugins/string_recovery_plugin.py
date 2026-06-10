import re
import logging
from pathlib import Path
from typing import Any, Dict, List

from decodeX.framework.plugin_base import Plugin, Finding

logger = logging.getLogger("decodeX.string_recovery")

class StringRecoveryPlugin(Plugin):
    """
    Recovers various encoded or fragmented strings.
    Supports UTF-16LE, Hex/Unicode escaped, and character arrays.
    """

    @property
    def name(self) -> str:
        return "string_recovery"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Recovers escaped, encoded, or fragmented strings (UTF-16, Hex, Unicode, CharArrays)."

    def analyze(self, target: Path | str | bytes) -> Dict[str, Any]:
        """
        Scan content for various string obfuscation patterns.
        """
        if isinstance(target, Path):
            try:
                content = target.read_text(errors="ignore")
                raw_bytes = target.read_bytes()
            except Exception:
                return {"error": "Could not read file."}
        elif isinstance(target, bytes):
            content = target.decode("latin-1", errors="ignore")
            raw_bytes = target
        else:
            content = str(target)
            raw_bytes = content.encode("latin-1", errors="ignore")

        results = []
        
        # 1. UTF-16LE Recovery (h\0e\0l\0l\0o\0 -> hello)
        if b"\x00" in raw_bytes:
            # Look for ASCII chars followed by nulls
            matches = re.findall(rb"([ -~]\x00){4,}", raw_bytes)
            if matches:
                try:
                    # Find the longest sequences and decode
                    utf16_str = raw_bytes.decode("utf-16le", errors="ignore")
                    # Clean up and check if readable
                    if len(utf16_str) > 5:
                        results.append({"type": "utf16le_string", "confidence": 0.9, "recovered": utf16_str[:500]})
                except Exception:
                    pass

        # 2. Hex Escaped Strings (\x68\x65\x6c\x6c\x6f)
        hex_escapes = re.findall(r"(?:\\x[0-9A-Fa-f]{2}){4,}", content)
        for he in hex_escapes:
            try:
                decoded = bytes.fromhex(he.replace("\\x", "")).decode("latin-1", errors="ignore")
                results.append({"type": "hex_escaped_string", "confidence": 1.0, "recovered": decoded})
            except Exception:
                continue

        # 3. Unicode Escaped Strings (\u0068\u0065\u006c)
        uni_escapes = re.findall(r"(?:\\u[0-9A-Fa-f]{4}){3,}", content)
        for ue in uni_escapes:
            try:
                decoded = ue.encode().decode("unicode_escape")
                results.append({"type": "unicode_escaped_string", "confidence": 1.0, "recovered": decoded})
            except Exception:
                continue

        # 4. Character Arrays ([104,101,108,108,111])
        char_arrays = re.findall(r"\[(?:\d{1,3},\s*){3,}\d{1,3}\]", content)
        for ca in char_arrays:
            try:
                nums = [int(n) for n in re.findall(r"\d+", ca)]
                if all(0 <= n <= 255 for n in nums):
                    decoded = "".join(chr(n) for n in nums)
                    results.append({"type": "char_array_string", "confidence": 0.9, "recovered": decoded})
            except Exception:
                continue

        findings = []
        for r in results:
            findings.append(Finding(
                severity="Low",
                category="Obfuscation",
                title=f"Recovered Obfuscated String ({r['type']})",
                evidence=f"Payload: {r['recovered'][:100]}...",
                recommendation="Review the recovered strings for URLs, file paths, or commands."
            ).to_dict())

        return {
            "results": results,
            "findings": findings
        }
