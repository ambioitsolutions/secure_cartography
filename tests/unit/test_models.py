"""
Tests for discovery data models (Interface, Neighbor, Device, DiscoveryResult).
"""

import json
from datetime import datetime, timedelta

import pytest

from sc2.scng.discovery.models import (
    Device,
    DeviceVendor,
    DiscoveryProtocol,
    DiscoveryResult,
    Interface,
    InterfaceStatus,
    Neighbor,
    NeighborProtocol,
)


# ---------------------------------------------------------------------------
# Interface
# ---------------------------------------------------------------------------

class TestInterface:
    """Tests for the Interface dataclass."""

    def test_creation_minimal(self):
        iface = Interface(name="Gi0/1")
        assert iface.name == "Gi0/1"
        assert iface.if_index is None
        assert iface.description is None
        assert iface.alias is None
        assert iface.ip_address is None
        assert iface.mac_address is None
        assert iface.speed_mbps is None
        assert iface.mtu is None
        assert iface.status == InterfaceStatus.UNKNOWN

    def test_creation_full(self):
        iface = Interface(
            name="Gi0/1",
            if_index=1,
            description="GigabitEthernet0/1",
            alias="Uplink to core",
            ip_address="10.0.0.1",
            mac_address="aa:bb:cc:dd:ee:ff",
            speed_mbps=1000,
            mtu=9000,
            status=InterfaceStatus.UP,
        )
        assert iface.name == "Gi0/1"
        assert iface.if_index == 1
        assert iface.description == "GigabitEthernet0/1"
        assert iface.alias == "Uplink to core"
        assert iface.ip_address == "10.0.0.1"
        assert iface.mac_address == "aa:bb:cc:dd:ee:ff"
        assert iface.speed_mbps == 1000
        assert iface.mtu == 9000
        assert iface.status == InterfaceStatus.UP

    def test_to_dict(self):
        iface = Interface(name="Gi0/1", if_index=1, status=InterfaceStatus.UP)
        d = iface.to_dict()
        assert d["name"] == "Gi0/1"
        assert d["if_index"] == 1
        assert d["status"] == "up"

    def test_to_dict_status_serialized_as_string(self):
        for status in InterfaceStatus:
            iface = Interface(name="eth0", status=status)
            d = iface.to_dict()
            assert d["status"] == status.value
            assert isinstance(d["status"], str)

    def test_from_dict(self):
        data = {
            "name": "Gi0/1",
            "if_index": 1,
            "description": None,
            "alias": None,
            "ip_address": None,
            "mac_address": None,
            "speed_mbps": 1000,
            "mtu": None,
            "status": "up",
        }
        iface = Interface.from_dict(data)
        assert iface.name == "Gi0/1"
        assert iface.if_index == 1
        assert iface.speed_mbps == 1000
        assert iface.status == InterfaceStatus.UP

    def test_to_dict_from_dict_roundtrip(self):
        original = Interface(
            name="et-0/0/0",
            if_index=42,
            description="100GE uplink",
            alias="To spine-1",
            ip_address="192.168.1.1",
            mac_address="00:11:22:33:44:55",
            speed_mbps=100000,
            mtu=9216,
            status=InterfaceStatus.DOWN,
        )
        restored = Interface.from_dict(original.to_dict())
        assert restored.name == original.name
        assert restored.if_index == original.if_index
        assert restored.description == original.description
        assert restored.alias == original.alias
        assert restored.ip_address == original.ip_address
        assert restored.mac_address == original.mac_address
        assert restored.speed_mbps == original.speed_mbps
        assert restored.mtu == original.mtu
        assert restored.status == original.status

    def test_from_dict_status_already_enum(self):
        """from_dict should handle status already being an InterfaceStatus."""
        data = {
            "name": "Gi0/1",
            "if_index": 1,
            "description": None,
            "alias": None,
            "ip_address": None,
            "mac_address": None,
            "speed_mbps": None,
            "mtu": None,
            "status": InterfaceStatus.ADMIN_DOWN,
        }
        iface = Interface.from_dict(data)
        assert iface.status == InterfaceStatus.ADMIN_DOWN


# ---------------------------------------------------------------------------
# Neighbor
# ---------------------------------------------------------------------------

class TestNeighbor:
    """Tests for the Neighbor dataclass."""

    def test_creation_minimal(self):
        neighbor = Neighbor(local_interface="Gi0/1")
        assert neighbor.local_interface == "Gi0/1"
        assert neighbor.remote_device == ""
        assert neighbor.remote_interface == ""
        assert neighbor.remote_ip is None
        assert neighbor.protocol == NeighborProtocol.CDP

    def test_creation_full(self):
        neighbor = Neighbor(
            local_interface="Gi0/1",
            local_interface_index=1,
            remote_device="switch-2",
            remote_interface="Gi0/0",
            remote_ip="10.0.1.1",
            remote_platform="Cisco WS-C3750",
            remote_description="Access switch",
            remote_capabilities="Bridge",
            protocol=NeighborProtocol.LLDP,
            chassis_id="aa:bb:cc:dd:ee:ff",
            chassis_id_subtype=4,
            port_id_subtype=5,
            raw_index="1.3",
        )
        assert neighbor.local_interface == "Gi0/1"
        assert neighbor.local_interface_index == 1
        assert neighbor.remote_device == "switch-2"
        assert neighbor.remote_interface == "Gi0/0"
        assert neighbor.remote_ip == "10.0.1.1"
        assert neighbor.remote_platform == "Cisco WS-C3750"
        assert neighbor.remote_description == "Access switch"
        assert neighbor.remote_capabilities == "Bridge"
        assert neighbor.protocol == NeighborProtocol.LLDP
        assert neighbor.chassis_id == "aa:bb:cc:dd:ee:ff"
        assert neighbor.chassis_id_subtype == 4
        assert neighbor.port_id_subtype == 5
        assert neighbor.raw_index == "1.3"

    def test_to_dict(self):
        neighbor = Neighbor(
            local_interface="Gi0/1",
            remote_device="switch-2",
            protocol=NeighborProtocol.CDP,
        )
        d = neighbor.to_dict()
        assert d["local_interface"] == "Gi0/1"
        assert d["remote_device"] == "switch-2"
        assert d["protocol"] == "cdp"
        assert isinstance(d["protocol"], str)

    def test_to_dict_protocol_serialized_as_string(self):
        for proto in NeighborProtocol:
            neighbor = Neighbor(local_interface="Gi0/1", protocol=proto)
            d = neighbor.to_dict()
            assert d["protocol"] == proto.value

    def test_from_dict(self):
        data = {
            "local_interface": "Gi0/1",
            "local_interface_index": 1,
            "remote_device": "switch-2",
            "remote_interface": "Gi0/0",
            "remote_ip": "10.0.1.1",
            "remote_platform": None,
            "remote_description": None,
            "remote_capabilities": None,
            "protocol": "lldp",
            "chassis_id": None,
            "chassis_id_subtype": None,
            "port_id_subtype": None,
            "raw_index": None,
        }
        neighbor = Neighbor.from_dict(data)
        assert neighbor.local_interface == "Gi0/1"
        assert neighbor.remote_device == "switch-2"
        assert neighbor.protocol == NeighborProtocol.LLDP

    def test_to_dict_from_dict_roundtrip(self):
        original = Neighbor(
            local_interface="Gi0/2",
            local_interface_index=2,
            remote_device="router-1",
            remote_interface="et-0/0/0",
            remote_ip="10.0.2.1",
            remote_platform="Juniper MX480",
            remote_description="Border router",
            remote_capabilities="Router",
            protocol=NeighborProtocol.LLDP,
            chassis_id="00:11:22:33:44:55",
            chassis_id_subtype=4,
            port_id_subtype=7,
            raw_index="2.5",
        )
        restored = Neighbor.from_dict(original.to_dict())
        assert restored.local_interface == original.local_interface
        assert restored.local_interface_index == original.local_interface_index
        assert restored.remote_device == original.remote_device
        assert restored.remote_interface == original.remote_interface
        assert restored.remote_ip == original.remote_ip
        assert restored.remote_platform == original.remote_platform
        assert restored.remote_description == original.remote_description
        assert restored.remote_capabilities == original.remote_capabilities
        assert restored.protocol == original.protocol
        assert restored.chassis_id == original.chassis_id
        assert restored.chassis_id_subtype == original.chassis_id_subtype
        assert restored.port_id_subtype == original.port_id_subtype
        assert restored.raw_index == original.raw_index

    def test_from_cdp(self):
        neighbor = Neighbor.from_cdp(
            local_interface="Gi0/1",
            device_id="switch-2.lab.local",
            remote_port="Gi1/0/24",
            ip_address="10.0.1.1",
            platform="Cisco WS-C3750",
            local_if_index=1,
            raw_index="4",
        )
        assert neighbor.local_interface == "Gi0/1"
        assert neighbor.local_interface_index == 1
        assert neighbor.remote_device == "switch-2.lab.local"
        assert neighbor.remote_interface == "Gi1/0/24"
        assert neighbor.remote_ip == "10.0.1.1"
        assert neighbor.remote_platform == "Cisco WS-C3750"
        assert neighbor.protocol == NeighborProtocol.CDP
        assert neighbor.raw_index == "4"

    def test_from_cdp_minimal(self):
        neighbor = Neighbor.from_cdp(
            local_interface="Gi0/1",
            device_id="switch-2",
            remote_port="Gi0/0",
        )
        assert neighbor.local_interface == "Gi0/1"
        assert neighbor.remote_device == "switch-2"
        assert neighbor.remote_interface == "Gi0/0"
        assert neighbor.remote_ip is None
        assert neighbor.remote_platform is None
        assert neighbor.local_interface_index is None
        assert neighbor.protocol == NeighborProtocol.CDP

    def test_from_lldp(self):
        neighbor = Neighbor.from_lldp(
            local_interface="Gi0/2",
            system_name="router-1.lab.local",
            port_id="ge-0/0/0",
            management_address="10.0.2.1",
            chassis_id="aa:bb:cc:dd:ee:ff",
            port_description="Uplink",
            system_description="Juniper Networks EX4300",
            capabilities="Router, Bridge",
            chassis_id_subtype=4,
            port_id_subtype=7,
            local_if_index=2,
            raw_index="7",
        )
        assert neighbor.local_interface == "Gi0/2"
        assert neighbor.local_interface_index == 2
        assert neighbor.remote_device == "router-1.lab.local"
        assert neighbor.remote_interface == "ge-0/0/0"
        assert neighbor.remote_ip == "10.0.2.1"
        assert neighbor.remote_description == "Juniper Networks EX4300"
        assert neighbor.remote_capabilities == "Router, Bridge"
        assert neighbor.protocol == NeighborProtocol.LLDP
        assert neighbor.chassis_id == "aa:bb:cc:dd:ee:ff"
        assert neighbor.chassis_id_subtype == 4
        assert neighbor.port_id_subtype == 7
        assert neighbor.raw_index == "7"

    def test_from_lldp_falls_back_to_chassis_id(self):
        """When system_name is None, remote_device falls back to chassis_id."""
        neighbor = Neighbor.from_lldp(
            local_interface="Gi0/1",
            system_name=None,
            chassis_id="aa:bb:cc:dd:ee:ff",
        )
        assert neighbor.remote_device == "aa:bb:cc:dd:ee:ff"

    def test_from_lldp_falls_back_to_empty_string(self):
        """When both system_name and chassis_id are None, remote_device is empty."""
        neighbor = Neighbor.from_lldp(
            local_interface="Gi0/1",
            system_name=None,
            chassis_id=None,
        )
        assert neighbor.remote_device == ""

    def test_from_lldp_port_id_none_becomes_empty(self):
        """When port_id is None, remote_interface defaults to empty string."""
        neighbor = Neighbor.from_lldp(
            local_interface="Gi0/1",
            port_id=None,
        )
        assert neighbor.remote_interface == ""

    def test_protocol_enum_values(self):
        assert NeighborProtocol.CDP.value == "cdp"
        assert NeighborProtocol.LLDP.value == "lldp"


# ---------------------------------------------------------------------------
# Device
# ---------------------------------------------------------------------------

class TestDevice:
    """Tests for the Device dataclass."""

    def test_creation_minimal(self):
        device = Device(hostname="switch-1", ip_address="10.0.0.1")
        assert device.hostname == "switch-1"
        assert device.ip_address == "10.0.0.1"
        assert device.sys_name is None
        assert device.vendor == DeviceVendor.UNKNOWN
        assert device.interfaces == []
        assert device.neighbors == []
        assert device.arp_table == {}
        assert device.discovered_via == DiscoveryProtocol.SNMP
        assert device.discovered_at is not None
        assert device.depth == 0
        assert device.discovery_success is True
        assert device.discovery_errors == []

    def test_post_init_sets_discovered_at(self):
        before = datetime.now()
        device = Device(hostname="switch-1", ip_address="10.0.0.1")
        after = datetime.now()
        assert before <= device.discovered_at <= after

    def test_post_init_preserves_explicit_discovered_at(self):
        explicit_time = datetime(2025, 1, 15, 12, 0, 0)
        device = Device(
            hostname="switch-1",
            ip_address="10.0.0.1",
            discovered_at=explicit_time,
        )
        assert device.discovered_at == explicit_time

    def test_creation_with_fixture(self, sample_device):
        """Verify the sample_device fixture is well-formed."""
        assert sample_device.hostname == "core-switch"
        assert sample_device.ip_address == "10.0.0.1"
        assert sample_device.vendor == DeviceVendor.CISCO
        assert len(sample_device.interfaces) == 2
        assert len(sample_device.neighbors) == 2

    def test_to_dict(self, sample_device):
        d = sample_device.to_dict()
        assert d["hostname"] == "core-switch"
        assert d["ip_address"] == "10.0.0.1"
        assert d["vendor"] == "cisco"
        assert d["discovered_via"] == "snmp"
        assert isinstance(d["interfaces"], list)
        assert len(d["interfaces"]) == 2
        assert isinstance(d["neighbors"], list)
        assert len(d["neighbors"]) == 2
        assert d["arp_table"] == {"aa:bb:cc:dd:ee:ff": "10.0.0.100"}
        assert isinstance(d["discovered_at"], str)

    def test_to_dict_discovered_at_iso_format(self):
        ts = datetime(2025, 6, 15, 10, 30, 0)
        device = Device(
            hostname="switch-1",
            ip_address="10.0.0.1",
            discovered_at=ts,
        )
        d = device.to_dict()
        assert d["discovered_at"] == "2025-06-15T10:30:00"

    def test_to_dict_discovered_at_none(self):
        """Even though __post_init__ sets it, test the serialization path for None."""
        device = Device(hostname="s1", ip_address="10.0.0.1")
        # Manually set to None to exercise that branch
        device.discovered_at = None
        d = device.to_dict()
        assert d["discovered_at"] is None

    def test_from_dict(self):
        data = {
            "hostname": "switch-1",
            "ip_address": "10.0.0.1",
            "sys_name": "switch-1.lab",
            "sys_descr": "Test device",
            "vendor": "cisco",
            "interfaces": [
                {
                    "name": "Gi0/1",
                    "if_index": 1,
                    "description": None,
                    "alias": None,
                    "ip_address": None,
                    "mac_address": None,
                    "speed_mbps": 1000,
                    "mtu": None,
                    "status": "up",
                }
            ],
            "neighbors": [
                {
                    "local_interface": "Gi0/1",
                    "local_interface_index": 1,
                    "remote_device": "router-1",
                    "remote_interface": "Gi0/0",
                    "remote_ip": "10.0.1.1",
                    "remote_platform": None,
                    "remote_description": None,
                    "remote_capabilities": None,
                    "protocol": "cdp",
                    "chassis_id": None,
                    "chassis_id_subtype": None,
                    "port_id_subtype": None,
                    "raw_index": None,
                }
            ],
            "arp_table": {"aa:bb:cc:00:00:01": "10.0.0.50"},
            "discovered_via": "snmp",
            "discovered_at": "2025-06-15T10:30:00",
            "depth": 1,
        }
        device = Device.from_dict(data)
        assert device.hostname == "switch-1"
        assert device.ip_address == "10.0.0.1"
        assert device.sys_name == "switch-1.lab"
        assert device.vendor == DeviceVendor.CISCO
        assert device.discovered_via == DiscoveryProtocol.SNMP
        assert device.discovered_at == datetime(2025, 6, 15, 10, 30, 0)
        assert device.depth == 1
        assert len(device.interfaces) == 1
        assert device.interfaces[0].name == "Gi0/1"
        assert device.interfaces[0].status == InterfaceStatus.UP
        assert len(device.neighbors) == 1
        assert device.neighbors[0].remote_device == "router-1"
        assert device.neighbors[0].protocol == NeighborProtocol.CDP
        assert device.arp_table == {"aa:bb:cc:00:00:01": "10.0.0.50"}

    def test_from_dict_defaults(self):
        """from_dict should apply sensible defaults for missing keys."""
        data = {"hostname": "s1", "ip_address": "10.0.0.1"}
        device = Device.from_dict(data)
        assert device.vendor == DeviceVendor.UNKNOWN
        assert device.discovered_via == DiscoveryProtocol.SNMP
        assert device.interfaces == []
        assert device.neighbors == []
        assert device.arp_table == {}
        assert device.depth == 0
        assert device.discovery_success is True
        assert device.discovery_errors == []

    def test_from_dict_discovered_at_none(self):
        data = {
            "hostname": "s1",
            "ip_address": "10.0.0.1",
            "discovered_at": None,
        }
        device = Device.from_dict(data)
        # __post_init__ will set it since from_dict passes None explicitly
        assert device.discovered_at is not None

    def test_to_dict_from_dict_roundtrip(self, sample_device):
        d = sample_device.to_dict()
        restored = Device.from_dict(d)
        assert restored.hostname == sample_device.hostname
        assert restored.ip_address == sample_device.ip_address
        assert restored.sys_name == sample_device.sys_name
        assert restored.sys_descr == sample_device.sys_descr
        assert restored.vendor == sample_device.vendor
        assert restored.discovered_via == sample_device.discovered_via
        assert restored.depth == sample_device.depth
        assert restored.arp_table == sample_device.arp_table
        assert len(restored.interfaces) == len(sample_device.interfaces)
        assert len(restored.neighbors) == len(sample_device.neighbors)
        for orig, rest in zip(sample_device.interfaces, restored.interfaces):
            assert rest.name == orig.name
            assert rest.if_index == orig.if_index
            assert rest.status == orig.status
        for orig, rest in zip(sample_device.neighbors, restored.neighbors):
            assert rest.remote_device == orig.remote_device
            assert rest.local_interface == orig.local_interface
            assert rest.protocol == orig.protocol

    def test_to_json(self, sample_device):
        json_str = sample_device.to_json()
        parsed = json.loads(json_str)
        assert parsed["hostname"] == "core-switch"
        assert parsed["ip_address"] == "10.0.0.1"
        assert parsed["vendor"] == "cisco"
        assert len(parsed["interfaces"]) == 2
        assert len(parsed["neighbors"]) == 2

    def test_to_json_indent(self):
        device = Device(hostname="s1", ip_address="10.0.0.1")
        json_str_4 = device.to_json(indent=4)
        parsed = json.loads(json_str_4)
        assert parsed["hostname"] == "s1"
        # Verify indentation is applied (4 spaces)
        assert "\n    " in json_str_4

    def test_add_neighbor(self):
        device = Device(hostname="s1", ip_address="10.0.0.1")
        neighbor = Neighbor.from_cdp(
            local_interface="Gi0/1",
            device_id="s2",
            remote_port="Gi0/0",
        )
        device.add_neighbor(neighbor)
        assert len(device.neighbors) == 1
        assert device.neighbors[0].remote_device == "s2"

    def test_add_neighbor_dedup_same_device_interface_protocol(self):
        """Adding a duplicate neighbor (same remote_device, local_interface, protocol) is a no-op."""
        device = Device(hostname="s1", ip_address="10.0.0.1")
        n1 = Neighbor.from_cdp(
            local_interface="Gi0/1",
            device_id="s2",
            remote_port="Gi0/0",
        )
        n2 = Neighbor.from_cdp(
            local_interface="Gi0/1",
            device_id="s2",
            remote_port="Gi0/0",
            ip_address="10.0.1.1",  # different detail, but same key fields
        )
        device.add_neighbor(n1)
        device.add_neighbor(n2)
        assert len(device.neighbors) == 1

    def test_add_neighbor_different_protocol_not_deduped(self):
        """Same device+interface but different protocol should not be deduped."""
        device = Device(hostname="s1", ip_address="10.0.0.1")
        cdp_neighbor = Neighbor.from_cdp(
            local_interface="Gi0/1",
            device_id="s2",
            remote_port="Gi0/0",
        )
        lldp_neighbor = Neighbor.from_lldp(
            local_interface="Gi0/1",
            system_name="s2",
            port_id="Gi0/0",
        )
        device.add_neighbor(cdp_neighbor)
        device.add_neighbor(lldp_neighbor)
        assert len(device.neighbors) == 2

    def test_add_neighbor_different_interface_not_deduped(self):
        """Same device+protocol but different local_interface should not be deduped."""
        device = Device(hostname="s1", ip_address="10.0.0.1")
        n1 = Neighbor.from_cdp(
            local_interface="Gi0/1",
            device_id="s2",
            remote_port="Gi0/0",
        )
        n2 = Neighbor.from_cdp(
            local_interface="Gi0/2",
            device_id="s2",
            remote_port="Gi0/1",
        )
        device.add_neighbor(n1)
        device.add_neighbor(n2)
        assert len(device.neighbors) == 2

    def test_cdp_neighbors_property(self, sample_device):
        cdp = sample_device.cdp_neighbors
        assert len(cdp) == 1
        assert all(n.protocol == NeighborProtocol.CDP for n in cdp)
        assert cdp[0].remote_device == "dist-switch-1"

    def test_lldp_neighbors_property(self, sample_device):
        lldp = sample_device.lldp_neighbors
        assert len(lldp) == 1
        assert all(n.protocol == NeighborProtocol.LLDP for n in lldp)
        assert lldp[0].remote_device == "dist-switch-2"

    def test_cdp_neighbors_empty(self):
        device = Device(hostname="s1", ip_address="10.0.0.1")
        assert device.cdp_neighbors == []

    def test_lldp_neighbors_empty(self):
        device = Device(hostname="s1", ip_address="10.0.0.1")
        assert device.lldp_neighbors == []

    def test_interface_by_index(self, sample_device):
        by_index = sample_device.interface_by_index
        assert 1 in by_index
        assert 2 in by_index
        assert by_index[1].name == "Gi0/1"
        assert by_index[2].name == "Gi0/2"

    def test_interface_by_index_skips_none(self):
        """Interfaces without if_index should be excluded from the dict."""
        device = Device(
            hostname="s1",
            ip_address="10.0.0.1",
            interfaces=[
                Interface(name="Gi0/1", if_index=1),
                Interface(name="Loopback0"),  # if_index is None
            ],
        )
        by_index = device.interface_by_index
        assert len(by_index) == 1
        assert 1 in by_index

    def test_interface_by_name(self, sample_device):
        by_name = sample_device.interface_by_name
        assert "Gi0/1" in by_name
        assert "Gi0/2" in by_name
        assert by_name["Gi0/1"].if_index == 1
        assert by_name["Gi0/2"].if_index == 2

    def test_interface_by_name_empty(self):
        device = Device(hostname="s1", ip_address="10.0.0.1")
        assert device.interface_by_name == {}

    def test_get_interface_name_found(self, sample_device):
        assert sample_device.get_interface_name(1) == "Gi0/1"
        assert sample_device.get_interface_name(2) == "Gi0/2"

    def test_get_interface_name_fallback(self, sample_device):
        assert sample_device.get_interface_name(999) == "ifIndex_999"

    def test_get_interface_name_fallback_no_interfaces(self):
        device = Device(hostname="s1", ip_address="10.0.0.1")
        assert device.get_interface_name(42) == "ifIndex_42"


# ---------------------------------------------------------------------------
# DiscoveryResult
# ---------------------------------------------------------------------------

class TestDiscoveryResult:
    """Tests for the DiscoveryResult dataclass."""

    def test_creation_empty(self):
        result = DiscoveryResult()
        assert result.devices == []
        assert result.total_attempted == 0
        assert result.successful == 0
        assert result.failed == 0
        assert result.skipped == 0
        assert result.excluded == 0
        assert result.started_at is None
        assert result.completed_at is None
        assert result.seed_devices == []
        assert result.max_depth == 0
        assert result.domains == []
        assert result.exclude_patterns == []

    def test_duration_seconds(self):
        start = datetime(2025, 6, 15, 10, 0, 0)
        end = datetime(2025, 6, 15, 10, 5, 30)
        result = DiscoveryResult(started_at=start, completed_at=end)
        assert result.duration_seconds == 330.0

    def test_duration_seconds_subsecond(self):
        start = datetime(2025, 6, 15, 10, 0, 0)
        end = start + timedelta(seconds=1.5)
        result = DiscoveryResult(started_at=start, completed_at=end)
        assert result.duration_seconds == 1.5

    def test_duration_seconds_none_when_not_started(self):
        result = DiscoveryResult()
        assert result.duration_seconds is None

    def test_duration_seconds_none_when_not_completed(self):
        result = DiscoveryResult(started_at=datetime.now())
        assert result.duration_seconds is None

    def test_devices_by_depth(self):
        d0a = Device(hostname="seed", ip_address="10.0.0.1", depth=0)
        d0b = Device(hostname="other-seed", ip_address="10.0.0.2", depth=0)
        d1 = Device(hostname="hop1", ip_address="10.0.1.1", depth=1)
        d2a = Device(hostname="hop2a", ip_address="10.0.2.1", depth=2)
        d2b = Device(hostname="hop2b", ip_address="10.0.2.2", depth=2)

        result = DiscoveryResult(devices=[d0a, d0b, d1, d2a, d2b])
        by_depth = result.devices_by_depth

        assert len(by_depth) == 3
        assert len(by_depth[0]) == 2
        assert len(by_depth[1]) == 1
        assert len(by_depth[2]) == 2
        assert by_depth[0][0].hostname == "seed"
        assert by_depth[0][1].hostname == "other-seed"
        assert by_depth[1][0].hostname == "hop1"

    def test_devices_by_depth_empty(self):
        result = DiscoveryResult()
        assert result.devices_by_depth == {}

    def test_to_dict(self, sample_device):
        start = datetime(2025, 6, 15, 10, 0, 0)
        end = datetime(2025, 6, 15, 10, 5, 30)
        result = DiscoveryResult(
            devices=[sample_device],
            total_attempted=3,
            successful=1,
            failed=1,
            skipped=1,
            excluded=0,
            started_at=start,
            completed_at=end,
            seed_devices=["10.0.0.1"],
            max_depth=2,
            domains=["lab.local"],
            exclude_patterns=["10.99.*"],
        )
        d = result.to_dict()
        assert len(d["devices"]) == 1
        assert d["devices"][0]["hostname"] == "core-switch"
        assert d["total_attempted"] == 3
        assert d["successful"] == 1
        assert d["failed"] == 1
        assert d["skipped"] == 1
        assert d["excluded"] == 0
        assert d["started_at"] == "2025-06-15T10:00:00"
        assert d["completed_at"] == "2025-06-15T10:05:30"
        assert d["duration_seconds"] == 330.0
        assert d["seed_devices"] == ["10.0.0.1"]
        assert d["max_depth"] == 2
        assert d["domains"] == ["lab.local"]
        assert d["exclude_patterns"] == ["10.99.*"]

    def test_to_dict_timestamps_none(self):
        result = DiscoveryResult()
        d = result.to_dict()
        assert d["started_at"] is None
        assert d["completed_at"] is None
        assert d["duration_seconds"] is None

    def test_to_json(self, sample_device):
        result = DiscoveryResult(
            devices=[sample_device],
            total_attempted=1,
            successful=1,
        )
        json_str = result.to_json()
        parsed = json.loads(json_str)
        assert parsed["total_attempted"] == 1
        assert len(parsed["devices"]) == 1


class TestDeviceVendorPica8:
    """Tests for PICA8 vendor enum value."""

    def test_pica8_enum_value(self):
        assert DeviceVendor.PICA8.value == "pica8"

    def test_pica8_from_string(self):
        assert DeviceVendor("pica8") == DeviceVendor.PICA8

    def test_device_with_pica8_vendor(self):
        d = Device(
            hostname="pica8-switch",
            ip_address="10.0.0.1",
            vendor=DeviceVendor.PICA8,
        )
        assert d.vendor == DeviceVendor.PICA8
        data = d.to_dict()
        assert data["vendor"] == "pica8"

    def test_pica8_roundtrip(self):
        d = Device(
            hostname="pica8-switch",
            ip_address="10.0.0.1",
            vendor=DeviceVendor.PICA8,
        )
        data = d.to_dict()
        d2 = Device.from_dict(data)
        assert d2.vendor == DeviceVendor.PICA8


class TestDeviceVendorMikroTik:
    """Tests for MIKROTIK vendor enum value."""

    def test_mikrotik_enum_value(self):
        assert DeviceVendor.MIKROTIK.value == "mikrotik"

    def test_mikrotik_from_string(self):
        assert DeviceVendor("mikrotik") == DeviceVendor.MIKROTIK

    def test_device_with_mikrotik_vendor(self):
        d = Device(
            hostname="mikrotik-switch",
            ip_address="10.0.0.1",
            vendor=DeviceVendor.MIKROTIK,
        )
        assert d.vendor == DeviceVendor.MIKROTIK
        data = d.to_dict()
        assert data["vendor"] == "mikrotik"

    def test_mikrotik_roundtrip(self):
        d = Device(
            hostname="mikrotik-switch",
            ip_address="10.0.0.1",
            vendor=DeviceVendor.MIKROTIK,
        )
        data = d.to_dict()
        d2 = Device.from_dict(data)
        assert d2.vendor == DeviceVendor.MIKROTIK
