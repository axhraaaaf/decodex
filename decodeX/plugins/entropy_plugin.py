"""Entropy analysis plugin."""

from pathlib import Path
from typing import Any

from decodeX.framework.plugin_base import Plugin
from decodeX.core.entropy_tools import calculate_shannon_entropy, explain_entropy_level


class EntropyPlugin(Plugin):
    """Plugin to calculate Shannon entropy."""

    @property
    def name(self) -> str:
        return "entropy"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Calculates Shannon entropy and provides a level classification."

    def analyze(self, target: Path | str | bytes) -> dict[str, Any]:
        """Analyze the target file's entropy."""
        if isinstance(target, bytes):
            data = target
        else:
            path = Path(target)
            try:
                data = path.read_bytes()
            except OSError as exc:
                raise OSError(f"Could not read file '{path}': {exc.strerror}") from exc

        entropy = calculate_shannon_entropy(data) if data else 0.0
        return {
            "score": round(entropy, 4),
            "level": explain_entropy_level(entropy),
        }
