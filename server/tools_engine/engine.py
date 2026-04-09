"""
Main dispatcher for simulated security audit tools.

Contains ``TOOL_DEFINITIONS`` (the 10 tool specs consumed by the LLM)
and ``execute_tool`` which routes to per-domain handler modules.
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from .network import handle_network_scan, handle_service_fingerprint, handle_vulnerability_scan
from .web import handle_web_crawl
from .testing import (
    handle_test_injection,
    handle_test_xss,
    handle_test_auth,
    handle_test_config,
    handle_test_crypto,
    handle_check_secrets,
)


# ---------------------------------------------------------------------------
# Tool definitions (same 10 tools as the original tools.py)
# ---------------------------------------------------------------------------

TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "network_scan",
        "description": "Discover hosts and open ports on a target network or host. Similar to nmap.",
        "parameters": {"target": "IP address or CIDR range (e.g., '10.0.1.0/24' or '10.0.1.10')"},
    },
    {
        "name": "service_fingerprint",
        "description": "Get detailed service version information for a specific host and port.",
        "parameters": {"host": "Target IP address", "port": "(optional) Specific port number"},
    },
    {
        "name": "web_crawl",
        "description": "Discover web endpoints and pages on a host's HTTP/HTTPS service.",
        "parameters": {"host": "Target IP address"},
    },
    {
        "name": "vulnerability_scan",
        "description": "Check a host's services against known CVE databases for vulnerable versions.",
        "parameters": {"host": "Target IP address"},
    },
    {
        "name": "test_injection",
        "description": "Test a web endpoint for injection vulnerabilities (SQL injection, command injection, SSRF, SSTI).",
        "parameters": {
            "host": "Target IP address",
            "endpoint": "URL path to test (e.g., '/api/login')",
            "parameter": "(optional) specific parameter to test",
        },
    },
    {
        "name": "test_xss",
        "description": "Test a web endpoint for Cross-Site Scripting (XSS) vulnerabilities.",
        "parameters": {
            "host": "Target IP address",
            "endpoint": "URL path to test",
            "parameter": "(optional) specific parameter to test",
        },
    },
    {
        "name": "test_auth",
        "description": "Test authentication and access controls -- default credentials, IDOR, brute force, session management.",
        "parameters": {
            "host": "Target IP address",
            "endpoint": "(optional) Specific endpoint to test",
            "parameter": "(optional) specific parameter to test",
        },
    },
    {
        "name": "test_config",
        "description": "Check for security misconfigurations -- exposed admin panels, directory listing, debug mode, open services.",
        "parameters": {"host": "Target IP address"},
    },
    {
        "name": "test_crypto",
        "description": "Analyze TLS/SSL configuration and cryptographic implementations.",
        "parameters": {"host": "Target IP address"},
    },
    {
        "name": "check_secrets",
        "description": "Scan for exposed secrets, API keys, credentials in accessible files and responses.",
        "parameters": {
            "host": "Target IP address",
            "endpoint": "(optional) Specific endpoint to check",
            "parameter": "(optional) specific parameter to test",
        },
    },
]


# ---------------------------------------------------------------------------
# Handler dispatch table
# ---------------------------------------------------------------------------

TOOL_HANDLERS = {
    "network_scan": handle_network_scan,
    "service_fingerprint": handle_service_fingerprint,
    "web_crawl": handle_web_crawl,
    "vulnerability_scan": handle_vulnerability_scan,
    "test_injection": handle_test_injection,
    "test_xss": handle_test_xss,
    "test_auth": handle_test_auth,
    "test_config": handle_test_config,
    "test_crypto": handle_test_crypto,
    "check_secrets": handle_check_secrets,
}


# ---------------------------------------------------------------------------
# Public entry point -- drop-in replacement for old tools.execute_tool
# ---------------------------------------------------------------------------

def execute_tool(
    tool_name: str,
    arguments: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
    discovered_vulns: Optional[Set[str]] = None,
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    """Execute a simulated tool and return (output, new_hosts, new_ports, reward).

    This is a drop-in replacement for the old ``tools.execute_tool``.
    """
    handler = TOOL_HANDLERS.get(tool_name)
    if not handler:
        return (f"Error: Unknown tool '{tool_name}'. Use list_tools to see available tools.", [], {}, -0.05)
    return handler(arguments, scenario, discovered_hosts, discovered_ports, discovered_vulns)
