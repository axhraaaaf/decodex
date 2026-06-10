from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    """Standardized finding model for all decodeX plugins."""
    severity: str  # Critical, High, Medium, Low, Info
    category: str
    title: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, str]:
        """Convert the finding to a dictionary."""
        return asdict(self)


class Plugin(ABC):
    """Abstract base class for all decodeX plugins."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return the plugin name."""
        pass
        
    @property
    @abstractmethod
    def version(self) -> str:
        """Return the plugin version."""
        pass
        
    @property
    @abstractmethod
    def description(self) -> str:
        """Return the plugin description."""
        pass

    @property
    def enabled(self) -> bool:
        """Whether the plugin is enabled by default."""
        return True

    @property
    def help_text(self) -> str:
        """Detailed help text for the plugin."""
        return self.description

    @abstractmethod
    def analyze(self, target: Path | str | bytes) -> dict[str, Any]:
        """Analyze the target and return results as a dictionary."""
        pass
