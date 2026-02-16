"""
SecureCartography NG - Topology Builder.

Extracted from engine.py for independent testing.
Builds validated topology maps from discovered device data.
"""

import logging
import re
from typing import Dict, List, Set, Any, Optional

logger = logging.getLogger(__name__)

from .models import Device


def extract_platform(sys_descr: Optional[str], vendor: Optional[str] = None) -> str:
    """
    Extract a concise platform string from sysDescr.

    Examples:
        "Arista Networks EOS version 4.33.1F running on an Arista vEOS-lab"
        -> "Arista vEOS-lab EOS 4.33.1F"

        "Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T..."
        -> "Cisco IOSv IOS 15.6(2)T"
    """
    if not sys_descr:
        return vendor or "Unknown"

    # Arista pattern
    if 'Arista' in sys_descr:
        model = "Arista"
        version = ""
        if 'vEOS-lab' in sys_descr:
            model = "Arista vEOS-lab"
        elif 'vEOS' in sys_descr:
            model = "Arista vEOS"
        eos_match = re.search(r'EOS version (\S+)', sys_descr)
        if eos_match:
            version = f"EOS {eos_match.group(1)}"
        return f"{model} {version}".strip()

    # Cisco IOS pattern
    if 'Cisco IOS' in sys_descr or 'Cisco' in sys_descr:
        model = "Cisco"
        if 'IOSv' in sys_descr or 'VIOS' in sys_descr:
            model = "Cisco IOSv"
        elif 'vios_l2' in sys_descr:
            model = "Cisco IOS"
        elif '7200' in sys_descr:
            model = "Cisco 7200"
        elif '7206VXR' in sys_descr:
            model = "Cisco 7206VXR"
        version_match = re.search(r'Version (\S+),', sys_descr)
        if version_match:
            return f"{model} IOS {version_match.group(1)}"
        return model

    # Juniper pattern
    if 'Juniper' in sys_descr or 'JUNOS' in sys_descr:
        version_match = re.search(r'JUNOS (\S+)', sys_descr)
        if version_match:
            return f"Juniper JUNOS {version_match.group(1)}"
        return "Juniper"

    # MikroTik RouterOS pattern
    # sysDescr format: "RouterOS CRS309-1G-8S+ 7.22beta6 (testing)"
    if 'MikroTik' in sys_descr or 'RouterOS' in sys_descr or 'routeros' in sys_descr.lower():
        model = "MikroTik"
        model_match = re.search(r'(C[A-Z]+\d+\S*)', sys_descr)
        if model_match:
            model = f"MikroTik {model_match.group(1)}"
        # Version is the numeric part (e.g., "7.22beta6", "7.11.2"), not the model
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?(?:beta|rc|alpha)?\d*)', sys_descr)
        if version_match:
            return f"{model} RouterOS {version_match.group(1)}"
        return model

    # Pica8 PicOS pattern
    # sysDescr from SNMP: "Pica8 S3410C-16TMS-P PicOS 4.7.1M-EC2"
    # sysDescr from SSH: cleaned show version output (may contain copyright text)
    if 'Pica8' in sys_descr or 'PicOS' in sys_descr or 'picos' in sys_descr.lower():
        model = "Pica8"
        # Match Pica8 hardware models (letter+digit patterns like S3410C-16TMS-P)
        model_match = re.search(r'([A-Z]\w*\d+\w*-\w+)', sys_descr)
        if model_match:
            candidate = model_match.group(1)
            # Exclude copyright year ranges like "2009-2026"
            if not re.match(r'^\d{4}-\d{4}$', candidate):
                model = f"Pica8 {candidate}"
        # PicOS version (e.g., 4.7.1M-EC2) — but strip build hash suffixes
        version_match = re.search(r'(?:PicOS|PICOS)\s+(\d+\.\d+\.\d+\S*)', sys_descr, re.IGNORECASE)
        if not version_match:
            version_match = re.search(r'(\d+\.\d+\.\d+[A-Za-z0-9\-]*)', sys_descr)
        if version_match:
            version = version_match.group(1)
            # Strip trailing build hash (e.g., "4.7.1M-EC2/858d9863c8" -> "4.7.1M-EC2")
            version = re.sub(r'/[0-9a-f]{6,}$', '', version)
            return f"{model} PicOS {version}"
        return model

    # Default: return first 50 chars
    return sys_descr[:50].strip()


class TopologyBuilder:
    """
    Builds a validated topology map from discovered devices.

    Connections are only included if:
    1. Both sides confirm the link (bidirectional), OR
    2. The peer wasn't discovered (leaf/edge case - trust unidirectional)

    This class is stateless and independently testable.
    """

    def build(self, devices: List[Device]) -> Dict[str, Any]:
        """
        Generate topology map from discovered devices with bidirectional validation.

        Returns a dict suitable for visualization:
        {
            "device_name": {
                "node_details": {"ip": "...", "platform": "..."},
                "peers": {
                    "peer_name": {
                        "ip": "...",
                        "platform": "...",
                        "connections": [["local_if", "remote_if"], ...]
                    }
                }
            }
        }
        """
        # Build lookup for device info by various identifiers
        device_info: Dict[str, Device] = {}
        for device in devices:
            if device.hostname:
                device_info[device.hostname] = device
            if device.sys_name and device.sys_name != device.hostname:
                device_info[device.sys_name] = device
            if device.ip_address:
                device_info[device.ip_address] = device

        def get_canonical_name(device: Device) -> str:
            return device.sys_name or device.hostname or device.ip_address

        def resolve_peer(peer_name: str, peer_ip: Optional[str] = None) -> str:
            """Resolve a neighbor reference to a canonical device name.

            Checks device_info by peer_name first, then by peer_ip.
            This handles cases where LLDP advertises a different hostname
            (e.g., "smf-core-01.yourdo") than the discovered device
            ("smf-core-01") but the IP matches.
            """
            if peer_name in device_info:
                return get_canonical_name(device_info[peer_name])
            if peer_ip and peer_ip in device_info:
                return get_canonical_name(device_info[peer_ip])
            return peer_name

        # Build set of discovered device canonical names
        discovered_devices: Set[str] = set()
        for device in devices:
            canonical = get_canonical_name(device)
            if canonical:
                discovered_devices.add(canonical)
                if device.sys_name:
                    discovered_devices.add(device.sys_name)
                if device.hostname:
                    discovered_devices.add(device.hostname)

        # First pass: collect all neighbor claims
        all_claims: Dict[tuple, List[tuple]] = {}

        for device in devices:
            device_canonical = get_canonical_name(device)
            if not device_canonical:
                continue

            for neighbor in device.neighbors:
                if not neighbor.remote_device:
                    continue

                local_if = normalize_interface(neighbor.local_interface)
                remote_if = normalize_interface(neighbor.remote_interface)

                if not local_if or not remote_if:
                    continue

                peer_name = neighbor.remote_device
                canonical_peer = resolve_peer(peer_name, neighbor.remote_ip)

                key = (device_canonical, local_if)
                if key not in all_claims:
                    all_claims[key] = []
                all_claims[key].append((canonical_peer, remote_if, neighbor))

        def _device_names(canonical: str) -> Set[str]:
            """Get all known names for a device."""
            names = {canonical}
            if canonical in device_info:
                dev = device_info[canonical]
                for n in [dev.hostname, dev.sys_name, dev.ip_address]:
                    if n:
                        names.add(n)
            return names

        def has_reverse_claim(device_canonical: str, local_if: str,
                              peer_canonical: str, remote_if: str) -> bool:
            """Check if peer claims the reverse connection.

            First tries exact interface match (peer:remote_if -> device:local_if).
            Falls back to device-level match: peer has ANY claim back to device
            on the same local interface. This handles LLDP port_id mismatches
            (e.g., Pica8 advertising description-style port IDs like
            "MikroTik sfpplus7 (ae2)" instead of "te-1/1/1").
            """
            device_names = _device_names(device_canonical)

            # Exact match: peer's remote_if claims back to device's local_if
            reverse_key = (peer_canonical, remote_if)
            if reverse_key in all_claims:
                for (claimed_peer, claimed_remote, _) in all_claims[reverse_key]:
                    if claimed_peer in device_names and claimed_remote == local_if:
                        return True

            # Fallback: peer has ANY interface claiming a link back to device
            # This handles LLDP port_id/description mismatches between vendors
            peer_names = _device_names(peer_canonical)
            for (claim_device, claim_if), claims in all_claims.items():
                if claim_device not in peer_names:
                    continue
                for (claimed_peer, claimed_remote, _) in claims:
                    if claimed_peer in device_names:
                        logger.debug(
                            "Accepted link %s:%s -> %s:%s via device-level match "
                            "(peer claims %s:%s -> %s:%s)",
                            device_canonical, local_if, peer_canonical, remote_if,
                            claim_device, claim_if, claimed_peer, claimed_remote,
                        )
                        return True

            return False

        def peer_was_discovered(peer_canonical: str, peer_name_original: str) -> bool:
            """Check if we discovered this peer."""
            if peer_canonical in discovered_devices:
                return True
            if peer_name_original in discovered_devices:
                return True
            if peer_name_original in device_info:
                return True
            return False

        def peer_is_leaf(peer_canonical: str, peer_name_original: str) -> bool:
            """Check if peer is a leaf node (no LLDP/CDP capability)."""
            if peer_canonical in device_info:
                peer_dev = device_info[peer_canonical]
                if len(peer_dev.neighbors) == 0:
                    return True
            if peer_name_original in device_info:
                peer_dev = device_info[peer_name_original]
                if len(peer_dev.neighbors) == 0:
                    return True
            return False

        # Second pass: build topology with validated connections
        topology: Dict[str, Any] = {}
        seen_devices: Set[str] = set()

        for device in devices:
            canonical_name = get_canonical_name(device)
            if not canonical_name or canonical_name in seen_devices:
                continue
            seen_devices.add(canonical_name)

            node = {
                "node_details": {
                    "ip": device.ip_address,
                    "platform": extract_platform(
                        device.sys_descr,
                        device.vendor.value if device.vendor else None,
                    ),
                },
                "peers": {},
            }

            peer_connections: Dict[str, Dict] = {}
            used_local_interfaces: Set[str] = set()

            for neighbor in device.neighbors:
                if not neighbor.remote_device:
                    continue

                local_if = normalize_interface(neighbor.local_interface)
                remote_if = normalize_interface(neighbor.remote_interface)

                if not local_if or not remote_if:
                    continue

                if local_if in used_local_interfaces:
                    continue

                peer_name = neighbor.remote_device
                canonical_peer = resolve_peer(peer_name, neighbor.remote_ip)

                peer_discovered = peer_was_discovered(canonical_peer, peer_name)

                if peer_discovered:
                    is_leaf = peer_is_leaf(canonical_peer, peer_name)
                    if is_leaf:
                        pass  # Trust unidirectional claim for leaf nodes
                    elif not has_reverse_claim(canonical_name, local_if, canonical_peer, remote_if):
                        logger.debug(
                            "Dropping unconfirmed link: %s:%s -> %s:%s",
                            canonical_name, local_if, canonical_peer, remote_if,
                        )
                        continue

                peer_platform = (
                    extract_platform(neighbor.remote_description)
                    if neighbor.remote_description
                    else None
                )
                # Look up peer device info by name or IP
                peer_dev_lookup = device_info.get(peer_name) or (
                    device_info.get(neighbor.remote_ip) if neighbor.remote_ip else None
                )
                if peer_dev_lookup:
                    peer_platform = extract_platform(
                        peer_dev_lookup.sys_descr,
                        peer_dev_lookup.vendor.value if peer_dev_lookup.vendor else None,
                    )

                if canonical_peer not in peer_connections:
                    peer_connections[canonical_peer] = {
                        "ip": neighbor.remote_ip,
                        "platform": peer_platform or "Unknown",
                        "connections": [],
                    }

                conn = [local_if, remote_if]
                peer_connections[canonical_peer]["connections"].append(conn)
                used_local_interfaces.add(local_if)

            node["peers"] = peer_connections
            topology[canonical_name] = node

        return topology


def normalize_interface(interface: str) -> str:
    """Normalize interface name for consistent display and deduplication."""
    if not interface:
        return ""

    result = interface.strip()

    # Cisco long-form to short-form
    cisco_replacements = [
        ("GigabitEthernet", "Gi"),
        ("TenGigabitEthernet", "Te"),
        ("TenGigE", "Te"),
        ("FortyGigabitEthernet", "Fo"),
        ("FortyGigE", "Fo"),
        ("HundredGigE", "Hu"),
        ("HundredGigabitEthernet", "Hu"),
        ("TwentyFiveGigE", "Twe"),
        ("FastEthernet", "Fa"),
        ("Ethernet", "Eth"),
    ]

    for long, short in cisco_replacements:
        if result.startswith(long):
            result = short + result[len(long):]
            break

    # Port-channel normalization
    port_channel_match = re.match(r'^[Pp]ort-[Cc]hannel(\d+.*)$', result)
    if port_channel_match:
        result = f"Po{port_channel_match.group(1)}"

    # Vlan normalization
    vlan_match = re.match(r'^[Vv][Ll][Aa][Nn]-?(\d+.*)$', result)
    if vlan_match:
        result = f"Vl{vlan_match.group(1)}"

    # Null interface
    if result.startswith("Null"):
        result = "Nu" + result[4:]

    # Loopback
    if result.startswith("Loopback"):
        result = "Lo" + result[8:]

    # Arista short form
    result = re.sub(r'^Et(\d)', r'Eth\1', result)

    # Juniper subinterface - strip default .0 unit
    result = re.sub(
        r'^((?:xe|ge|et|ae|irb|em|me|fxp)-?\d+(?:/\d+)*)\.0$',
        r'\1',
        result,
        flags=re.IGNORECASE,
    )

    return result


def connections_equal(conn1: List[str], conn2: List[str]) -> bool:
    """Check if two connections are equivalent (same interfaces, normalized)."""
    if len(conn1) != 2 or len(conn2) != 2:
        return False

    local1, remote1 = normalize_interface(conn1[0]), normalize_interface(conn1[1])
    local2, remote2 = normalize_interface(conn2[0]), normalize_interface(conn2[1])

    return local1 == local2 and remote1 == remote2
