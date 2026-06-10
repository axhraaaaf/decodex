import base64
import re
import logging
from pathlib import Path
from typing import Any, Dict, List

from decodeX.framework.plugin_base import Plugin, Finding
from decodeX.core.ioc_extractor import get_malware_score

logger = logging.getLogger("decodeX.powershell_decoder")

class PowerShellDecoderPlugin(Plugin):
    """
    Deobfuscates PowerShell commands and payloads.
    Detects -enc, -EncodedCommand, and UTF-16LE Base64 payloads.
    """

    @property
    def name(self) -> str:
        return "powershell_decoder"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Detects and decodes encoded PowerShell commands and payloads."

    def analyze(self, target: Path | str | bytes) -> Dict[str, Any]:
        """
        Search for PowerShell encoded commands and decode them.
        """
        # Convert input to string
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
        
        # 1. Search for -enc, -EncodedCommand, etc.
        # Pattern: powershell(.exe)? ... -e(nc(odedcommand)?)? <base64>
        ps_pattern = re.compile(r"(?:powershell|pwsh)(?:\.exe)?\s+.*-(?:e|en|enc|encoded|encodedcommand)\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
        
        for match in ps_pattern.finditer(content):
            b64_str = match.group(1)
            try:
                # PowerShell uses UTF-16LE for encoded commands
                decoded_bytes = base64.b64decode(b64_str)
                decoded_script = decoded_bytes.decode("utf-16le", errors="ignore")
                
                malware_info = get_malware_score(decoded_script)
                
                results.append({
                    "type": "powershell_encoded_command",
                    "confidence": 1.0,
                    "original_match": match.group(0),
                    "decoded_script": decoded_script,
                    "malware_info": malware_info
                })
            except Exception as e:
                logger.debug(f"Failed to decode PS candidate: {e}")

        # 2. Search for standalone large Base64 blobs that look like PowerShell (UTF-16LE encoded)
        # Often found in direct scripts or dropped files
        standalone_b64 = re.findall(r"\b[A-Za-z0-9+/]{30,}={0,2}\b", content)
        for b64_candidate in standalone_b64:
            try:
                decoded_bytes = base64.b64decode(b64_candidate)
                # UTF-16LE check: often has null bytes every second char
                if len(decoded_bytes) > 20 and sum(1 for i in range(1, len(decoded_bytes), 2) if decoded_bytes[i] == 0) / (len(decoded_bytes)//2) > 0.8:
                    decoded_script = decoded_bytes.decode("utf-16le", errors="ignore")
                    if "powershell" in decoded_script.lower() or "invoke-" in decoded_script.lower():
                        results.append({
                            "type": "standalone_ps_blob",
                            "confidence": 0.8,
                            "decoded_script": decoded_script,
                            "malware_info": get_malware_score(decoded_script)
                        })
            except Exception:
                continue

        findings = []
        for r in results:
            findings.append(Finding(
                severity="High",
                category="Execution",
                title=f"Detected Encoded PowerShell Command ({r['type']})",
                evidence=f"Match: {r.get('original_match', 'Standalone blob')}",
                recommendation="Analyze the decoded script for malicious network activity or system changes."
            ).to_dict())

        return {
            "results": results,
            "findings": findings
        }
