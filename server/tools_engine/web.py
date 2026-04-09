"""
Web-layer tool handler: web_crawl.

Discovers web endpoints and parameters on a host's HTTP/HTTPS service
using scenario ground-truth data.
"""

from typing import Any, Dict, List, Optional, Set, Tuple


def handle_web_crawl(
    args: Dict[str, Any],
    scenario: Dict[str, Any],
    discovered_hosts: List[str],
    discovered_ports: Dict[str, List[int]],
    discovered_vulns: Optional[Set[str]] = None,
) -> Tuple[str, List[str], Dict[str, List[int]], float]:
    """Crawl web endpoints.  Returns endpoints WITH parameters."""
    host = args.get("host", "")
    dv = discovered_vulns or set()

    host_info_raw = scenario.get("hosts", {}).get(host)
    if host_info_raw:
        required = host_info_raw.get("hidden_until", [])
        if required and not all(r in dv for r in required):
            return (
                f"Error: Host {host} not reachable. It may be on an internal network segment.",
                [], {}, -0.02,
            )

    endpoints = scenario.get("web_endpoints", {}).get(host, [])

    if not endpoints:
        return (f"No web endpoints found on {host}. Host may not run a web server.", [], {}, 0.0)

    lines = [
        f"Web crawl results for {host}:",
        f"  Discovered {len(endpoints)} endpoint(s):",
        "",
    ]
    for ep in endpoints:
        method = ep.get("method", "GET")
        path = ep.get("path", "/")
        desc = ep.get("description", "")
        lines.append(f"  {method:6s} {path:30s} -- {desc}")

        # Show parameters if available
        params = ep.get("params")
        if params:
            param_parts = []
            for p in params:
                if isinstance(p, dict):
                    param_parts.append(f"{p.get('name', p)} ({p.get('type', 'string')})")
                else:
                    param_parts.append(f"{p} (string)")
            lines.append(f"         Parameters: {', '.join(param_parts)}")

    lines.append(f"\n{len(endpoints)} endpoint(s) discovered. Test each for vulnerabilities.")
    return "\n".join(lines), [], {}, 0.03
