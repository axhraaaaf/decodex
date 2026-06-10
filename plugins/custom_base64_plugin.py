import base64
import logging
import string
from pathlib import Path
import re
from typing import Any, Dict, List

from decodeX.framework.plugin_base import Plugin, Finding
from decodeX.core.detection_engine import score_language

logger = logging.getLogger("decodeX.custom_base64")

STANDARD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

class CustomBase64Plugin(Plugin):
    """
    Detects and attempts to decode content using custom Base64 alphabets.
    """

    @property
    def name(self) -> str:
        return "custom_base64"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Identifies and reconstructs custom Base64 alphabet substitutions."

    def analyze(self, target: Path | str | bytes) -> Dict[str, Any]:
        """
        Analyze content for non-standard Base64 patterns.
        """
        if isinstance(target, Path):
            try:
                content = target.read_text(errors="ignore")
            except Exception:
                return {"error": "Could not read file."}
        elif isinstance(target, bytes):
            content = target.decode("latin-1", errors="ignore")
        else:
            content = str(target)

        # 1. Detection: High-entropy strings of length 64 that could be an alphabet
        # Malware often includes the custom alphabet as a string literal
        alphabet_candidates = re.findall(r"\b[A-Za-z0-9+/=_-]{64}\b", content)
        
        results = []
        for cand in alphabet_candidates:
            if len(set(cand)) == 64:
                results.append({
                    "type": "potential_alphabet",
                    "alphabet": cand,
                    "confidence": 0.9,
                    "diff": self._get_alphabet_diff(cand)
                })

        findings = []
        for r in results:
            findings.append(Finding(
                severity="Medium",
                category="Obfuscation",
                title="Detected Potential Custom Base64 Alphabet",
                evidence=f"Alphabet: {r['alphabet']}",
                recommendation="Use this alphabet to decode suspicious Base64 blocks in the sample."
            ).to_dict())

        return {
            "results": results,
            "findings": findings
        }

    def _get_alphabet_diff(self, alphabet: str) -> Dict[str, str]:
        diff = {}
        for i, char in enumerate(alphabet):
            if char != STANDARD_ALPHABET[i]:
                diff[STANDARD_ALPHABET[i]] = char
        return diff

    def decode_with_alphabet(self, data: str, alphabet: str) -> str:
        """Helper to decode data using a custom alphabet."""
        trans = str.maketrans(alphabet, STANDARD_ALPHABET)
        translated = data.translate(trans)
        try:
            return base64.b64decode(translated).decode("latin-1", errors="ignore")
        except Exception:
            return ""
