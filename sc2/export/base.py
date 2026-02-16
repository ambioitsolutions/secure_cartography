"""
SecureCartography v2 - Shared Exporter Base.

Extracts common topology pre-processing logic shared between
DrawioExporter and GraphMLExporter.
"""

import re
from dataclasses import dataclass
from typing import Dict, Set


@dataclass
class Connection:
    """Represents a single port-to-port connection."""
    local_port: str
    remote_port: str


# Compiled once, shared across all exporters
MAC_PATTERN = re.compile(r'^([0-9a-f]{4}\.){2}[0-9a-f]{4}$', re.IGNORECASE)

# Keywords indicating an endpoint device
ENDPOINT_KEYWORDS = frozenset({
    'endpoint', 'camera', 'phone', 'printer', 'pc', 'workstation',
})


def is_endpoint(node_id: str, platform: str) -> bool:
    """
    Determine if a node is an endpoint device.

    Checks MAC address format and platform keywords.
    """
    if MAC_PATTERN.match(node_id):
        return True
    platform_lower = platform.lower() if platform else ''
    return any(kw in platform_lower for kw in ENDPOINT_KEYWORDS)


def preprocess_topology(
    data: Dict,
    include_endpoints: bool = True,
    connected_only: bool = False,
) -> Dict:
    """
    Normalize topology and apply filters.

    - Creates entries for referenced but undefined peers
    - Optionally filters out endpoint devices
    - Optionally filters out standalone (unconnected) nodes

    Args:
        data: SC2 map-format topology dict.
        include_endpoints: If False, remove endpoint nodes.
        connected_only: If True, remove nodes with no connections.

    Returns:
        Filtered copy of topology dict.
    """
    # Find all referenced nodes
    defined = set(data.keys())
    referenced: Set[str] = set()

    for node_data in data.values():
        if isinstance(node_data, dict) and 'peers' in node_data:
            referenced.update(node_data['peers'].keys())

    # Add undefined nodes as endpoints
    result = data.copy()
    for node_id in referenced - defined:
        result[node_id] = {
            'node_details': {'ip': '', 'platform': 'endpoint'},
            'peers': {},
        }

    # Filter endpoints if requested
    if not include_endpoints:
        endpoints = {
            nid for nid, ndata in result.items()
            if is_endpoint(nid, ndata.get('node_details', {}).get('platform', ''))
        }

        filtered = {}
        for node_id, node_data in result.items():
            if node_id not in endpoints:
                node_copy = node_data.copy()
                if 'peers' in node_copy:
                    node_copy['peers'] = {
                        pid: pdata for pid, pdata in node_copy['peers'].items()
                        if pid not in endpoints
                    }
                filtered[node_id] = node_copy
        result = filtered

    # Filter unconnected nodes if requested
    if connected_only:
        connected_nodes: Set[str] = set()
        for node_id, node_data in result.items():
            if isinstance(node_data, dict):
                peers = node_data.get('peers', {})
                if peers:
                    connected_nodes.add(node_id)
                    connected_nodes.update(peers.keys())

        result = {nid: ndata for nid, ndata in result.items() if nid in connected_nodes}

    return result
