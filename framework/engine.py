"""Core analysis engine for decodeX."""

import logging
from pathlib import Path
from typing import Any, Dict, List

from decodeX.framework.plugin_manager import PluginManager

logger = logging.getLogger(__name__)

class Engine:
    """Core engine that manages plugin execution and aggregates results."""

    def __init__(self, plugin_manager: PluginManager):
        """Initialize the engine with a provided PluginManager."""
        self.plugin_manager = plugin_manager
        # Ensure plugins are loaded
        if not self.plugin_manager.get_all_plugins():
            self.plugin_manager.load_plugins()

    def analyze(self, target: Path | str | bytes) -> List[Dict[str, Any]]:
        """
        Execute all enabled plugins on the given target.
        
        Returns a list of results in the format:
        [
            {
                "plugin": "plugin_name",
                "result": {...}
            },
            ...
        ]
        """
        aggregated_results = []
        plugins = self.plugin_manager.get_all_plugins()

        for plugin in plugins:
            if not plugin.enabled:
                continue
                
            plugin_output = {}
            try:
                # Safely execute the plugin
                result = plugin.analyze(target)
                plugin_output = {
                    "plugin": plugin.name,
                    "result": result
                }
            except Exception as e:
                logger.error(f"Plugin '{plugin.name}' raised an error during analysis: {e}")
                plugin_output = {
                    "plugin": plugin.name,
                    "result": {"error": str(e)}
                }
            finally:
                aggregated_results.append(plugin_output)
                
        return aggregated_results
