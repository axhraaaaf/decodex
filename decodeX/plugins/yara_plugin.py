import os
import yara
from pathlib import Path
from typing import Any, Dict, List

from decodeX.framework.plugin_base import Plugin

class YaraPlugin(Plugin):
    """Plugin to perform signature-based detection using YARA."""

    def __init__(self):
        super().__init__()
        self.rules_dir = Path(__file__).parent.parent / "rules"
        self.rules = None
        self._compile_rules()

    def _compile_rules(self):
        """Compile all .yar files in the rules directory."""
        if not self.rules_dir.exists():
            return

        rule_files = {}
        for yar_file in self.rules_dir.glob("*.yar"):
            rule_files[yar_file.name] = str(yar_file)

        if rule_files:
            try:
                self.rules = yara.compile(filepaths=rule_files)
            except yara.Error as e:
                # Store compilation error to report during analyze phase
                self.compilation_error = str(e)
            except Exception as e:
                self.compilation_error = f"Unexpected YARA error: {e}"
        else:
            self.compilation_error = "No .yar files found in rules directory."

    def analyze(self, target_path: Path) -> Dict[str, Any]:
        """Execute YARA rules against the target file."""
        findings = []
        matches_summary = []
        
        if not self.rules:
            error_msg = getattr(self, "compilation_error", "YARA rules not initialized.")
            return {"error": error_msg}

        try:
            matches = self.rules.match(str(target_path))
            for match in matches:
                matches_summary.append(match.rule)
                findings.append({
                    "rule": match.rule,
                    "tags": match.tags,
                    "metadata": match.meta,
                    "matches": len(match.strings)
                })
        except Exception as e:
            return {"error": f"Error during YARA scan: {e}"}

        return {
            "matches": matches_summary,
            "detailed_findings": findings,
            "count": len(matches_summary)
        }
