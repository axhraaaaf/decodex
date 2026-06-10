from pathlib import Path
from typing import Any
import logging

from decodeX.framework.plugin_base import Plugin, Finding
from decodeX.core.encodings import auto_detect, decode_pipeline

logger = logging.getLogger("decodeX.plugins.encodings")

class EncodingsPlugin(Plugin):
    """
    Plugin for automatic detection and multi-layer decoding of common encodings.
    Integrates the core/encodings.py module into the decodeX framework.
    """

    @property
    def name(self) -> str:
        return "encodings"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Detects and decodes Base64, Base32, Base58, Hex, ROT, Caesar, etc."

    def analyze(self, target: Path | str | bytes) -> dict[str, Any]:
        """Framework entry point for analysis."""
        # Convert target to string input
        input_data = ""
        if isinstance(target, Path):
            try:
                input_data = target.read_text(errors="replace")
            except Exception as e:
                logger.error(f"Failed to read file target: {e}")
                return {"error": f"Failed to read file: {e}"}
        elif isinstance(target, bytes):
            input_data = target.decode("utf-8", errors="replace")
        else:
            input_data = str(target)

        # Use the requested run() method internal logic
        return self.run(input_data)

    def run(self, input_data: str) -> dict[str, Any]:
        """
        Specific requirement: expose all decoding methods through a single run() method.
        This performs auto-detection and pipeline decoding.
        """
        logger.info(f"Starting decoding run for input (len: {len(input_data)})")
        
        # 1. Get raw auto-detection results
        raw_candidates = auto_detect(input_data)
        
        # 2. Run the full multi-layer pipeline
        pipeline_result = decode_pipeline(input_data)
        
        # 3. Build the requested output structure
        results = []
        for cand in raw_candidates:
            results.append({
                "decoder": cand["type"],
                "output": cand["output"],
                "confidence": cand["confidence"]
            })
            
        best_guess = results[0]["decoder"] if results else "none"
        
        # Standard decodeX finding integration
        findings = []
        if pipeline_result["steps"]:
            findings.append(Finding(
                severity="Medium",
                category="Encoding",
                title=f"Detected nested encoding ({best_guess})",
                evidence=f"Pipeline result: {pipeline_result['output'][:100]}...",
                recommendation="Review the decoded content for suspicious indicators or secondary payloads."
            ).to_dict())

        return {
            "input": input_data,
            "results": results,
            "best_guess": best_guess,
            "pipeline": {
                "final_output": pipeline_result["output"],
                "steps": pipeline_result["steps"],
                "depth": len(pipeline_result["steps"])
            },
            "findings": findings
        }
