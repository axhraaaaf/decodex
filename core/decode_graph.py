import json
from typing import Any, Dict, List, Optional

class DecodeNode:
    """A node in the transformation graph."""
    def __init__(self, node_type: str, confidence: float = 1.0, metadata: Optional[Dict[str, Any]] = None):
        self.node_type = node_type
        self.confidence = confidence
        self.children: List['DecodeNode'] = []
        self.metadata = metadata or {}
        self.depth = 0

    def add_child(self, child: 'DecodeNode'):
        child.depth = self.depth + 1
        self.children.append(child)

    def to_dict(self) -> Dict[str, Any]:
        """Export the graph to a JSON-serializable dictionary."""
        return {
            "type": self.node_type,
            "confidence": round(self.confidence, 4),
            "depth": self.depth,
            "metadata": self.metadata,
            "children": [child.to_dict() for child in self.children]
        }

    def render_tree(self, prefix: str = "", is_last: bool = True) -> str:
        """Render the graph as a console tree string."""
        connector = "+-- " if is_last else "|-- "
        line = f"{prefix}{connector}{self.node_type} (conf: {self.confidence:.2f})\n"
        
        new_prefix = prefix + ("    " if is_last else "|   ")
        for i, child in enumerate(self.children):
            line += child.render_tree(new_prefix, i == len(self.children) - 1)
            
        return line

def build_graph_from_chain(chain: List[Dict[str, Any]]) -> DecodeNode:
    """Helper to build a linear tree from a flat chain."""
    root = DecodeNode("input", 1.0)
    current = root
    
    for step in chain:
        child = DecodeNode(step["decoder"], step["confidence"])
        current.add_child(child)
        current = child
        
    return root
