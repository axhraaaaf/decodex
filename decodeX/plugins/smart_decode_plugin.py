import json
import logging
from pathlib import Path
from typing import Any, Dict

from decodeX.framework.plugin_base import Plugin, Finding
from decodeX.core.decode_pipeline import decode_chain
from decodeX.core.decode_graph import build_graph_from_chain
from decodeX.core.entropy_tools import calculate_shannon_entropy

logger = logging.getLogger("decodeX.smart_decode_plugin")

class SmartDecodePlugin(Plugin):
    """
    Tier 1 Next-Generation Decoding Engine.
    Intelligently identifies, ranks, chains, and visualizes decoding operations.
    """

    @property
    def name(self) -> str:
        return "smart_decode"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Next-gen intelligent decoding system with transformation graphing."

    def analyze(self, target: Path | str | bytes) -> Dict[str, Any]:
        """
        Coordinates detection, pipelining, and graph generation.
        """
        # 1. Prepare data
        input_data = b""
        if isinstance(target, Path):
            try:
                input_data = target.read_bytes()
            except Exception as e:
                return {"error": f"Failed to read file: {e}"}
        elif isinstance(target, bytes):
            input_data = target
        else:
            input_data = str(target).encode("latin-1", errors="ignore")

        if not input_data:
            return {"error": "Empty input."}

        # 2. Performance Safeguard (Sample limit for very large files)
        # We process the first 64KB for full analysis
        sample_size = 65536
        analysis_blob = input_data[:sample_size]
        
        # 3. Initial Entropy Analysis
        entropy = calculate_shannon_entropy(analysis_blob)
        
        # 4. Run Smart Decode Pipeline
        # We try both latin-1 and utf-16 if it looks like UTF-16
        try:
            # Simple check for UTF-16
            if len(analysis_blob) >= 2 and (analysis_blob[:2] == b"\xff\xfe" or analysis_blob[:2] == b"\xfe\xff"):
                input_text = analysis_blob.decode("utf-16", errors="ignore")
            else:
                input_text = analysis_blob.decode("latin-1", errors="ignore")
        except Exception:
            input_text = analysis_blob.decode("latin-1", errors="ignore")

        logger.info(f"Starting smart decode for blob (len={len(analysis_blob)}, entropy={entropy:.2f})")
        result = decode_chain(input_text)
        
        # 5. Build Graph
        graph = build_graph_from_chain(result["chain"])
        
        # 6. Generate Findings
        findings = []
        if result["chain"]:
            findings.append(Finding(
                severity="Medium" if result["overall_confidence"] > 0.8 else "Low",
                category="Obfuscation",
                title=f"Detected nested transformation chain ({len(result['chain'])} layers)",
                evidence=f"Chain: {' -> '.join([s['decoder'] for s in result['chain']])}",
                recommendation="Examine the final payload for malicious indicators."
            ).to_dict())
            
        # 7. Final Response
        return {
            "entropy": round(entropy, 2),
            "best_chain": [s["decoder"] for s in result["chain"]],
            "chain_details": result["chain"],
            "final_output": result["final_output"],
            "confidence": result["overall_confidence"],
            "readability_score": result.get("readability_score", 0),
            "graph": graph.to_dict(),
            "tree_view": graph.render_tree(),
            "findings": findings
        }

    def run(self, data: str | bytes) -> Dict[str, Any]:
        """Programmatic access to the smart decoder."""
        return self.analyze(data)
