"""Plugin manager for decodeX."""

import importlib
import inspect
import pkgutil
import logging
from typing import List, Type, Optional

from decodeX.framework.plugin_base import Plugin

logger = logging.getLogger(__name__)

class PluginManager:
    """Manager for discovering, loading, and accessing decodeX plugins."""
    
    def __init__(self, plugins_package: str = "decodeX.plugins"):
        self.plugins_package = plugins_package
        self._plugins: List[Plugin] = []
        
    def load_plugins(self) -> List[Plugin]:
        """Dynamically discover, load, and instantiate all plugins."""
        self._plugins = []
        
        try:
            package = importlib.import_module(self.plugins_package)
        except ImportError as e:
            logger.error(f"Failed to import plugins package '{self.plugins_package}': {e}")
            return []

        package_path = getattr(package, "__path__", None)
        if not package_path:
            logger.warning(f"Plugins package '{self.plugins_package}' has no __path__ attribute.")
            return []

        for _, module_name, is_pkg in pkgutil.iter_modules(package_path):
            full_module_name = f"{self.plugins_package}.{module_name}"
            try:
                module = importlib.import_module(full_module_name)
            except Exception as e:
                logger.warning(f"Failed to load plugin module '{full_module_name}': {e}")
                continue
                
            for attribute_name in dir(module):
                attribute = getattr(module, attribute_name)
                
                if (
                    inspect.isclass(attribute)
                    and issubclass(attribute, Plugin)
                    and attribute is not Plugin
                    and not inspect.isabstract(attribute)
                ):
                    try:
                        plugin_instance = attribute()
                        self._plugins.append(plugin_instance)
                    except Exception as e:
                        logger.error(f"Failed to initialize plugin '{attribute_name}' in '{full_module_name}': {e}")
                    
        return self.get_all_plugins()
        
    def get_all_plugins(self) -> List[Plugin]:
        """Return a list of all currently loaded plugins."""
        return self._plugins

    def get_plugin(self, name: str) -> Optional[Plugin]:
        """Get a specific plugin by name."""
        for plugin in self._plugins:
            if plugin.name == name:
                return plugin
        return None
