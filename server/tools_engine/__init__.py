"""
Dynamic tool simulation engine (KB-driven).

Drop-in replacement for the monolithic ``server/tools.py``.
Exports the same two symbols with identical signatures:

    TOOL_DEFINITIONS : List[Dict]
    execute_tool(tool_name, arguments, scenario, discovered_hosts,
                 discovered_ports, discovered_vulns) -> Tuple[str, List[str], Dict[str, List[int]], float]
"""

from .engine import TOOL_DEFINITIONS, execute_tool

__all__ = ["TOOL_DEFINITIONS", "execute_tool"]
