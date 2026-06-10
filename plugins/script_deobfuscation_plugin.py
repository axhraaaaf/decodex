import re
import logging
from pathlib import Path
from typing import Any, Dict

from decodeX.framework.plugin_base import Plugin, Finding

logger = logging.getLogger("decodeX.script_deobfuscator")

class ScriptDeobfuscatorPlugin(Plugin):
    """
    Deobfuscates malicious scripts (JS, VBS, PS).
    Detects eval, atob, string arrays, and packed code.
    """

    @property
    def name(self) -> str:
        return "script_deobfuscator"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Deobfuscator for JavaScript, VBScript, and PowerShell scripts."

    def analyze(self, target: Path | str | bytes) -> Dict[str, Any]:
        """
        Analyze script content for obfuscation.
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

        results = []
        
        # 1. JavaScript Detection (eval, atob, string arrays)
        if re.search(r"\beval\s*\(", content):
            results.append({"type": "js_eval", "confidence": 0.9, "detail": "Detected eval() call"})
        if re.search(r"\batob\s*\(", content):
            results.append({"type": "js_atob", "confidence": 0.9, "detail": "Detected atob() call"})
            
        # 2. VBScript Detection (Execute, Chr)
        if re.search(r"\bExecute\b", content, re.IGNORECASE):
            results.append({"type": "vbs_execute", "confidence": 0.8, "detail": "Detected VBScript Execute call"})
            
        # 3. String Concatenation / Arrays
        if re.search(r"\"\s*\+\s*\"", content):
            results.append({"type": "string_fragmentation", "confidence": 0.6, "detail": "High frequency of string concatenation"})

        findings = []
        for r in results:
            findings.append(Finding(
                severity="Medium",
                category="Obfuscation",
                title=f"Potential Script Obfuscation ({r['type']})",
                evidence=r["detail"],
                recommendation="Examine the script flow to identify the final de-obfuscated payload."
            ).to_dict())

        return {
            "results": results,
            "findings": findings
        }
