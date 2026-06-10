"""Hash calculation plugin."""

import hashlib
from pathlib import Path

from decodeX.framework.plugin_base import Plugin


class HashPlugin(Plugin):
    """Plugin to calculate file hashes."""

    @property
    def name(self) -> str:
        return "hashes"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Calculates MD5 and SHA256 hashes."

    def analyze(self, target: Path | str | bytes) -> dict[str, str]:
        """Analyze the target file's hashes."""
        if isinstance(target, bytes):
            data = target
        else:
            path = Path(target)
            try:
                data = path.read_bytes()
            except OSError as exc:
                raise OSError(f"Could not read file '{path}': {exc.strerror}") from exc

        return {
            "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
