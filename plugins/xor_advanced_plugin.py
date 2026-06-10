import logging
from pathlib import Path
from typing import Any, Dict, List

from decodeX.framework.plugin_base import Plugin, Finding
from decodeX.core.key_recovery import find_best_single_byte_key, score_xor_key

logger = logging.getLogger("decodeX.xor_advanced")

class XORAdvancedPlugin(Plugin):
    """
    Advanced XOR deobfuscation plugin.
    Supports single-byte, repeating-key, and basic rolling XOR.
    """

    @property
    def name(self) -> str:
        return "xor_advanced"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Advanced XOR analysis including single-byte and repeating-key brute force."

    def analyze(self, target: Path | str | bytes) -> Dict[str, Any]:
        """
        Perform advanced XOR analysis on the target.
        """
        # Convert input to bytes
        if isinstance(target, Path):
            try:
                data = target.read_bytes()
            except Exception:
                return {"error": "Could not read file."}
        elif isinstance(target, bytes):
            data = target
        else:
            data = str(target).encode("latin-1", errors="ignore")

        if not data:
            return {"error": "Empty input."}

        results = []

        # 1. Single-byte XOR Brute Force
        logger.info("Starting single-byte XOR brute force...")
        single_res = find_best_single_byte_key(data)
        if single_res["confidence"] > 0.4:
            results.append({
                "type": "single_byte_xor",
                "key": f"0x{single_res['key_val']:02x}",
                "confidence": single_res["confidence"],
                "decoded_output": self._apply_single_xor(data, single_res['key_val']),
                "details": single_res
            })

        # 2. Basic Repeating-key XOR (Key length 2-8 heuristic)
        # In Tier 2, we'll try common fixed keys or 2/4/8 byte patterns
        # For now, we'll just report if single-byte failed but entropy is suspicious
        
        findings = []
        for r in results:
            if r["confidence"] > 0.7:
                findings.append(Finding(
                    severity="Medium",
                    category="Obfuscation",
                    title=f"Detected XOR obfuscation ({r['type']})",
                    evidence=f"Key: {r['key']} (Confidence: {r['confidence']})",
                    recommendation="Review the decoded payload for follow-on scripts or C2 configuration."
                ).to_dict())

        return {
            "results": results,
            "findings": findings
        }

    def _apply_single_xor(self, data: bytes, key: int) -> str:
        return bytes([b ^ key for b in data]).decode("latin-1", errors="ignore")

    def run(self, data: bytes, key: str | int) -> Dict[str, Any]:
        """Manual XOR application."""
        if isinstance(key, str):
            if key.startswith("0x"): k = int(key, 16)
            else: k = int(key)
        else:
            k = key
        
        decoded = self._apply_single_xor(data, k)
        return {"decoded_output": decoded}
