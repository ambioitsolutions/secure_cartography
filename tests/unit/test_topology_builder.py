"""
Tests for TopologyBuilder - bidirectional validation, normalization, platform extraction.

Covers the refactored topology_builder.py module extracted from engine.py.
Includes regression tests for the has_reverse_claim bug fix (Phase 2.1).
"""

import pytest

from sc2.scng.discovery.topology_builder import (
    TopologyBuilder,
    normalize_interface,
    connections_equal,
    extract_platform,
)
from sc2.scng.discovery.models import (
    Device, Neighbor, Interface, DeviceVendor,
    NeighborProtocol, InterfaceStatus,
)


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def make_device(
    hostname, ip, sys_name=None, sys_descr=None, vendor=DeviceVendor.UNKNOWN,
    neighbors=None, interfaces=None,
):
    return Device(
        hostname=hostname,
        ip_address=ip,
        sys_name=sys_name or hostname,
        sys_descr=sys_descr,
        vendor=vendor,
        neighbors=neighbors or [],
        interfaces=interfaces or [],
    )


def make_cdp_neighbor(local_if, remote_device, remote_if, remote_ip=None):
    return Neighbor.from_cdp(
        local_interface=local_if,
        device_id=remote_device,
        remote_port=remote_if,
        ip_address=remote_ip,
    )


def make_lldp_neighbor(local_if, system_name, port_id, mgmt_ip=None, sys_descr=None):
    return Neighbor.from_lldp(
        local_interface=local_if,
        system_name=system_name,
        port_id=port_id,
        management_address=mgmt_ip,
        system_description=sys_descr,
    )


# ===========================================================================
# normalize_interface tests
# ===========================================================================

class TestNormalizeInterface:
    """Test interface name normalization rules."""

    # Cisco long-form to short-form
    @pytest.mark.parametrize("input_if,expected", [
        ("GigabitEthernet0/0", "Gi0/0"),
        ("GigabitEthernet0/0/0", "Gi0/0/0"),
        ("TenGigabitEthernet1/0/1", "Te1/0/1"),
        ("TenGigE0/0/0/1", "Te0/0/0/1"),
        ("FortyGigabitEthernet1/0/1", "Fo1/0/1"),
        ("FortyGigE1/0/1", "Fo1/0/1"),
        ("HundredGigE0/0/0/0", "Hu0/0/0/0"),
        ("HundredGigabitEthernet0/0/0/0", "Hu0/0/0/0"),
        ("TwentyFiveGigE1/0/1", "Twe1/0/1"),
        ("FastEthernet0/1", "Fa0/1"),
        ("Ethernet1/1", "Eth1/1"),
    ])
    def test_cisco_long_to_short(self, input_if, expected):
        assert normalize_interface(input_if) == expected

    # Port-channel normalization
    @pytest.mark.parametrize("input_if,expected", [
        ("Port-channel1", "Po1"),
        ("Port-Channel1", "Po1"),
        ("port-channel10", "Po10"),
    ])
    def test_port_channel(self, input_if, expected):
        assert normalize_interface(input_if) == expected

    # Vlan normalization
    @pytest.mark.parametrize("input_if,expected", [
        ("Vlan100", "Vl100"),
        ("VLAN200", "Vl200"),
        ("vlan-300", "Vl300"),
    ])
    def test_vlan(self, input_if, expected):
        assert normalize_interface(input_if) == expected

    def test_null_interface(self):
        assert normalize_interface("Null0") == "Nu0"

    def test_loopback(self):
        assert normalize_interface("Loopback0") == "Lo0"

    # Arista short-form Et -> Eth
    def test_arista_short_form(self):
        assert normalize_interface("Et1/1") == "Eth1/1"
        assert normalize_interface("Et49/1") == "Eth49/1"

    # Juniper .0 stripping
    @pytest.mark.parametrize("input_if,expected", [
        ("xe-0/0/0.0", "xe-0/0/0"),
        ("ge-0/0/1.0", "ge-0/0/1"),
        ("et-0/0/0.0", "et-0/0/0"),
        ("ae0.0", "ae0"),
        ("irb0.0", "irb0"),
        ("em0.0", "em0"),
        ("me0.0", "me0"),
        ("fxp0.0", "fxp0"),
    ])
    def test_juniper_strip_unit_zero(self, input_if, expected):
        assert normalize_interface(input_if) == expected

    # Juniper: keep non-zero units
    @pytest.mark.parametrize("input_if,expected", [
        ("ge-0/0/1.100", "ge-0/0/1.100"),
        ("xe-0/0/0.512", "xe-0/0/0.512"),
        ("ae0.42", "ae0.42"),
    ])
    def test_juniper_keep_nonzero_unit(self, input_if, expected):
        assert normalize_interface(input_if) == expected

    # Edge cases
    def test_empty_string(self):
        assert normalize_interface("") == ""

    def test_none_returns_empty(self):
        assert normalize_interface(None) == ""

    def test_already_short_form(self):
        assert normalize_interface("Gi0/0") == "Gi0/0"

    def test_strips_whitespace(self):
        assert normalize_interface("  GigabitEthernet0/0  ") == "Gi0/0"

    # Juniper case insensitivity
    def test_juniper_case_insensitive(self):
        assert normalize_interface("Xe-0/0/0.0") == "Xe-0/0/0"
        assert normalize_interface("GE-0/0/1.0") == "GE-0/0/1"


# ===========================================================================
# connections_equal tests
# ===========================================================================

class TestConnectionsEqual:
    def test_identical_connections(self):
        assert connections_equal(["Gi0/0", "xe-0/0/0"], ["Gi0/0", "xe-0/0/0"])

    def test_normalized_connections(self):
        assert connections_equal(
            ["GigabitEthernet0/0", "xe-0/0/0.0"],
            ["Gi0/0", "xe-0/0/0"],
        )

    def test_different_connections(self):
        assert not connections_equal(["Gi0/0", "xe-0/0/0"], ["Gi0/1", "xe-0/0/0"])

    def test_wrong_length(self):
        assert not connections_equal(["Gi0/0"], ["Gi0/0", "xe-0/0/0"])
        assert not connections_equal(["Gi0/0", "xe-0/0/0", "extra"], ["Gi0/0", "xe-0/0/0"])


# ===========================================================================
# extract_platform tests
# ===========================================================================

class TestExtractPlatform:
    def test_cisco_iosv(self):
        desc = "Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE"
        assert extract_platform(desc) == "Cisco IOSv IOS 15.6(2)T"

    def test_cisco_7200(self):
        desc = "Cisco IOS Software, 7200 Software (C7200-ADVIPSERVICESK9-M), Version 15.2(4)S"
        assert "Cisco 7200" in extract_platform(desc)

    def test_arista_veos_lab(self):
        desc = "Arista Networks EOS version 4.33.1F running on an Arista vEOS-lab"
        assert extract_platform(desc) == "Arista vEOS-lab EOS 4.33.1F"

    def test_arista_veos(self):
        desc = "Arista Networks EOS version 4.20.15M running on vEOS"
        assert extract_platform(desc) == "Arista vEOS EOS 4.20.15M"

    def test_juniper(self):
        desc = "Juniper Networks, Inc. vmx internet router, kernel JUNOS 22.3R1.11"
        assert extract_platform(desc) == "Juniper JUNOS 22.3R1.11"

    def test_none_returns_unknown(self):
        assert extract_platform(None) == "Unknown"

    def test_none_with_vendor_fallback(self):
        assert extract_platform(None, "cisco") == "cisco"

    def test_unknown_vendor_truncation(self):
        long_desc = "a" * 100
        result = extract_platform(long_desc)
        assert len(result) <= 50

    def test_cisco_generic(self):
        assert extract_platform("Cisco something") == "Cisco"


# ===========================================================================
# TopologyBuilder.build() tests
# ===========================================================================

class TestTopologyBuilder:
    """Test topology building with bidirectional validation."""

    def setup_method(self):
        self.builder = TopologyBuilder()

    def test_empty_devices(self):
        result = self.builder.build([])
        assert result == {}

    def test_single_device_no_neighbors(self):
        dev = make_device("sw1", "10.0.0.1", sys_descr="Cisco IOS")
        result = self.builder.build([dev])
        assert "sw1" in result
        assert result["sw1"]["peers"] == {}

    def test_bidirectional_link_included(self):
        """Both devices claim the link -> link should appear."""
        dev_a = make_device("sw-a", "10.0.0.1", vendor=DeviceVendor.CISCO, neighbors=[
            make_cdp_neighbor("Gi0/1", "sw-b", "Gi0/0", "10.0.0.2"),
        ])
        dev_b = make_device("sw-b", "10.0.0.2", vendor=DeviceVendor.CISCO, neighbors=[
            make_cdp_neighbor("Gi0/0", "sw-a", "Gi0/1", "10.0.0.1"),
        ])

        result = self.builder.build([dev_a, dev_b])

        assert "sw-b" in result["sw-a"]["peers"]
        assert result["sw-a"]["peers"]["sw-b"]["connections"] == [["Gi0/1", "Gi0/0"]]

    def test_unidirectional_link_dropped_for_discovered_peer(self):
        """Only A claims link to B, B has other neighbors -> drop."""
        dev_a = make_device("sw-a", "10.0.0.1", neighbors=[
            make_cdp_neighbor("Gi0/1", "sw-b", "Gi0/0", "10.0.0.2"),
        ])
        # sw-b has a neighbor to sw-c but NOT back to sw-a
        dev_b = make_device("sw-b", "10.0.0.2", neighbors=[
            make_cdp_neighbor("Gi0/2", "sw-c", "Gi0/0", "10.0.0.3"),
        ])
        dev_c = make_device("sw-c", "10.0.0.3", neighbors=[
            make_cdp_neighbor("Gi0/0", "sw-b", "Gi0/2", "10.0.0.2"),
        ])

        result = self.builder.build([dev_a, dev_b, dev_c])

        # sw-a -> sw-b should be DROPPED (no reverse claim, sw-b is not leaf)
        assert "sw-b" not in result["sw-a"]["peers"]

    def test_leaf_node_trusts_unidirectional(self):
        """Discovered peer with 0 neighbors (leaf) trusts unidirectional."""
        dev_a = make_device("sw-a", "10.0.0.1", neighbors=[
            make_cdp_neighbor("Gi0/1", "leaf-1", "Gi0/0", "10.0.0.2"),
        ])
        # leaf-1 is discovered but has NO neighbors (e.g., a host or endpoint)
        dev_leaf = make_device("leaf-1", "10.0.0.2", neighbors=[])

        result = self.builder.build([dev_a, dev_leaf])

        # Link should be included because leaf-1 is a leaf node
        assert "leaf-1" in result["sw-a"]["peers"]

    def test_undiscovered_peer_trusts_unidirectional(self):
        """Peer not in device list -> trust unidirectional claim."""
        dev_a = make_device("sw-a", "10.0.0.1", neighbors=[
            make_cdp_neighbor("Gi0/1", "external-router", "Gi0/0", "10.0.1.1"),
        ])

        result = self.builder.build([dev_a])

        # external-router wasn't discovered, so unidirectional is trusted
        assert "external-router" in result["sw-a"]["peers"]

    def test_canonical_name_uses_sys_name(self):
        """sys_name takes precedence over hostname for canonical name."""
        dev = make_device("10.0.0.1", "10.0.0.1", sys_name="core-rtr.lab.local")
        result = self.builder.build([dev])
        assert "core-rtr.lab.local" in result
        assert "10.0.0.1" not in result

    def test_device_deduplication(self):
        """Same device appearing twice (same sys_name) only appears once."""
        dev1 = make_device("sw1", "10.0.0.1", sys_name="sw1")
        dev2 = make_device("sw1", "10.0.0.1", sys_name="sw1")
        result = self.builder.build([dev1, dev2])
        assert len(result) == 1

    def test_duplicate_local_interface_skipped(self):
        """Second neighbor on same local interface is ignored."""
        dev = make_device("sw1", "10.0.0.1", neighbors=[
            make_cdp_neighbor("Gi0/1", "sw2", "Gi0/0"),
            make_cdp_neighbor("Gi0/1", "sw3", "Gi0/0"),  # same local interface
        ])
        result = self.builder.build([dev])
        # Only one peer should use Gi0/1
        total_connections = sum(
            len(peer["connections"])
            for peer in result["sw1"]["peers"].values()
        )
        assert total_connections == 1

    def test_platform_extraction_in_node_details(self):
        """Node details should contain parsed platform string."""
        dev = make_device(
            "sw1", "10.0.0.1",
            sys_descr="Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE",
            vendor=DeviceVendor.CISCO,
        )
        result = self.builder.build([dev])
        assert result["sw1"]["node_details"]["platform"] == "Cisco IOSv IOS 15.6(2)T"

    def test_skip_neighbor_with_no_remote_device(self):
        """Neighbors without remote_device should be skipped."""
        dev = make_device("sw1", "10.0.0.1", neighbors=[
            Neighbor(local_interface="Gi0/1", remote_device="", remote_interface="Gi0/0"),
        ])
        result = self.builder.build([dev])
        assert result["sw1"]["peers"] == {}

    def test_skip_neighbor_with_empty_interfaces(self):
        """Neighbors with empty local or remote interface should be skipped."""
        dev = make_device("sw1", "10.0.0.1", neighbors=[
            Neighbor(local_interface="", remote_device="sw2", remote_interface="Gi0/0"),
            Neighbor(local_interface="Gi0/1", remote_device="sw2", remote_interface=""),
        ])
        result = self.builder.build([dev])
        assert result["sw1"]["peers"] == {}

    # -----------------------------------------------------------------------
    # Multi-vendor cross-link tests (regression from audit)
    # -----------------------------------------------------------------------

    def test_cisco_juniper_cross_link(self):
        """Cisco Gi0/0 <-> Juniper ge-0/0/0.0 should match after normalization."""
        cisco = make_device("cisco-rtr", "10.0.0.1", vendor=DeviceVendor.CISCO, neighbors=[
            make_cdp_neighbor("GigabitEthernet0/0", "juniper-sw", "ge-0/0/0.0", "10.0.0.2"),
        ])
        juniper = make_device("juniper-sw", "10.0.0.2", vendor=DeviceVendor.JUNIPER, neighbors=[
            make_lldp_neighbor("ge-0/0/0", "cisco-rtr", "GigabitEthernet0/0", "10.0.0.1"),
        ])

        result = self.builder.build([cisco, juniper])

        # Normalized: Gi0/0 <-> ge-0/0/0 (Juniper .0 stripped)
        assert "juniper-sw" in result["cisco-rtr"]["peers"]
        conns = result["cisco-rtr"]["peers"]["juniper-sw"]["connections"]
        assert conns == [["Gi0/0", "ge-0/0/0"]]

    def test_cisco_arista_cross_link(self):
        """Cisco Gi0/1 <-> Arista Et1/1 should match via normalization."""
        cisco = make_device("cisco-rtr", "10.0.0.1", vendor=DeviceVendor.CISCO, neighbors=[
            make_cdp_neighbor("GigabitEthernet0/1", "arista-sw", "Et1/1", "10.0.0.2"),
        ])
        arista = make_device("arista-sw", "10.0.0.2", vendor=DeviceVendor.ARISTA, neighbors=[
            make_lldp_neighbor("Ethernet1/1", "cisco-rtr", "GigabitEthernet0/1", "10.0.0.1"),
        ])

        result = self.builder.build([cisco, arista])

        # Normalized: Gi0/1 <-> Eth1/1
        assert "arista-sw" in result["cisco-rtr"]["peers"]
        conns = result["cisco-rtr"]["peers"]["arista-sw"]["connections"]
        assert conns == [["Gi0/1", "Eth1/1"]]

    def test_juniper_arista_cross_link(self):
        """Juniper xe-0/0/0.0 <-> Arista Et49/1 should match."""
        juniper = make_device("juniper-sw", "10.0.0.1", vendor=DeviceVendor.JUNIPER, neighbors=[
            make_lldp_neighbor("xe-0/0/0.0", "arista-sw", "Et49/1", "10.0.0.2"),
        ])
        arista = make_device("arista-sw", "10.0.0.2", vendor=DeviceVendor.ARISTA, neighbors=[
            make_lldp_neighbor("Ethernet49/1", "juniper-sw", "xe-0/0/0", "10.0.0.1"),
        ])

        result = self.builder.build([juniper, arista])

        # Normalized: xe-0/0/0 <-> Eth49/1
        assert "arista-sw" in result["juniper-sw"]["peers"]
        conns = result["juniper-sw"]["peers"]["arista-sw"]["connections"]
        assert conns == [["xe-0/0/0", "Eth49/1"]]

    def test_reverse_claim_with_hostname_mismatch(self):
        """Reverse claim should match when peer uses IP instead of hostname."""
        dev_a = make_device("sw-a", "10.0.0.1", neighbors=[
            make_cdp_neighbor("Gi0/1", "sw-b", "Gi0/0", "10.0.0.2"),
        ])
        # sw-b knows sw-a by IP address, not hostname
        dev_b = make_device("sw-b", "10.0.0.2", neighbors=[
            make_cdp_neighbor("Gi0/0", "10.0.0.1", "Gi0/1", "10.0.0.1"),
        ])

        result = self.builder.build([dev_a, dev_b])

        # Should still match because device_info maps IP to Device
        assert "sw-b" in result["sw-a"]["peers"]

    def test_port_channel_bidirectional(self):
        """Port-channel links should validate bidirectionally."""
        sw1 = make_device("sw1", "10.0.0.1", neighbors=[
            make_cdp_neighbor("Port-channel1", "sw2", "Port-Channel1", "10.0.0.2"),
        ])
        sw2 = make_device("sw2", "10.0.0.2", neighbors=[
            make_cdp_neighbor("port-channel1", "sw1", "Port-channel1", "10.0.0.1"),
        ])

        result = self.builder.build([sw1, sw2])

        # All normalize to Po1
        assert "sw2" in result["sw1"]["peers"]
        conns = result["sw1"]["peers"]["sw2"]["connections"]
        assert conns == [["Po1", "Po1"]]

    def test_three_device_ring_topology(self):
        """Three switches in a ring - all bidirectional links should appear."""
        sw1 = make_device("sw1", "10.0.0.1", neighbors=[
            make_cdp_neighbor("Gi0/1", "sw2", "Gi0/0", "10.0.0.2"),
            make_cdp_neighbor("Gi0/2", "sw3", "Gi0/0", "10.0.0.3"),
        ])
        sw2 = make_device("sw2", "10.0.0.2", neighbors=[
            make_cdp_neighbor("Gi0/0", "sw1", "Gi0/1", "10.0.0.1"),
            make_cdp_neighbor("Gi0/1", "sw3", "Gi0/1", "10.0.0.3"),
        ])
        sw3 = make_device("sw3", "10.0.0.3", neighbors=[
            make_cdp_neighbor("Gi0/0", "sw1", "Gi0/2", "10.0.0.1"),
            make_cdp_neighbor("Gi0/1", "sw2", "Gi0/1", "10.0.0.2"),
        ])

        result = self.builder.build([sw1, sw2, sw3])

        # All three devices should have 2 peers each
        assert len(result["sw1"]["peers"]) == 2
        assert len(result["sw2"]["peers"]) == 2
        assert len(result["sw3"]["peers"]) == 2


# ---------------------------------------------------------------------------
# PicOS extract_platform
# ---------------------------------------------------------------------------

class TestExtractPlatformPicOS:
    """Tests for PicOS platform extraction."""

    def test_pica8_with_model_and_version(self):
        result = extract_platform(
            "Pica8 S3410C-16TMS-P PicOS 4.7.1M"
        )
        assert "Pica8" in result
        assert "PicOS" in result
        assert "4.7.1M" in result

    def test_picos_version_only(self):
        result = extract_platform("PicOS 4.7.1M-EC2")
        assert "Pica8" in result
        assert "4.7.1M-EC2" in result

    def test_pica8_vendor_fallback(self):
        result = extract_platform("Pica8 switch")
        assert "Pica8" in result

    def test_picos_lowercase(self):
        result = extract_platform("picos version 3.2.1")
        assert "Pica8" in result


class TestTopologyBuilderPicOSCrossLinks:
    """Verify PicOS cross-links with Cisco and FortiGate neighbors."""

    def test_picos_to_cisco_bidirectional(self):
        """PicOS switch ge-1/1/17 <-> Cisco Gi0/9"""
        picos_dev = make_device(
            "smf-core01-pica8", "10.17.50.5",
            sys_descr="Pica8 PicOS 4.7.1M",
            vendor=DeviceVendor.PICA8,
            neighbors=[
                make_lldp_neighbor("ge-1/1/17", "smf-core-01", "Gi0/9", "10.17.109.5"),
            ],
        )
        cisco_dev = make_device(
            "smf-core-01", "10.17.109.5",
            sys_descr="Cisco IOS Software, Version 15.2(4)M",
            vendor=DeviceVendor.CISCO,
            neighbors=[
                make_lldp_neighbor("Gi0/9", "smf-core01-pica8", "ge-1/1/17", "10.17.50.5"),
            ],
        )
        topo = TopologyBuilder().build([picos_dev, cisco_dev])
        assert "smf-core01-pica8" in topo
        peers = topo["smf-core01-pica8"]["peers"]
        assert "smf-core-01" in peers
        conns = peers["smf-core-01"]["connections"]
        assert len(conns) == 1
        assert conns[0] == ["ge-1/1/17", "Gi0/9"]

    def test_picos_with_undiscovered_fortinet_peer(self):
        """PicOS switch sees FortiGate neighbor that wasn't discovered."""
        picos_dev = make_device(
            "smf-core01-pica8", "10.17.50.5",
            sys_descr="Pica8 PicOS 4.7.1M",
            vendor=DeviceVendor.PICA8,
            neighbors=[
                make_lldp_neighbor("ge-1/1/9", "fw01", "lan2"),
                make_lldp_neighbor("ge-1/1/10", "fw01", "lan3"),
            ],
        )
        topo = TopologyBuilder().build([picos_dev])
        peers = topo["smf-core01-pica8"]["peers"]
        assert "fw01" in peers
        conns = peers["fw01"]["connections"]
        assert len(conns) == 2

    def test_picos_interface_normalization(self):
        """PicOS ge-1/1/X and te-1/1/X interfaces pass through normalization."""
        assert normalize_interface("ge-1/1/17") == "ge-1/1/17"
        assert normalize_interface("te-1/1/1") == "te-1/1/1"
        assert normalize_interface("ae1") == "ae1"


# ---------------------------------------------------------------------------
# MikroTik extract_platform
# ---------------------------------------------------------------------------

class TestExtractPlatformMikroTik:
    """Tests for MikroTik platform extraction."""

    def test_mikrotik_with_model_and_version(self):
        result = extract_platform(
            "MikroTik CRS309-1G-8S+ RouterOS 7.22beta6"
        )
        assert "MikroTik" in result
        assert "RouterOS" in result
        assert "7.22beta6" in result

    def test_routeros_version_only(self):
        result = extract_platform("RouterOS 7.11.2")
        assert "MikroTik" in result
        assert "7.11.2" in result

    def test_mikrotik_vendor_fallback(self):
        result = extract_platform("MikroTik router")
        assert "MikroTik" in result

    def test_mikrotik_model_pattern(self):
        result = extract_platform("MikroTik CRS326-24G-2S+ RouterOS 7.15")
        assert "CRS326" in result


class TestTopologyBuilderMikroTikCrossLinks:
    """Verify MikroTik cross-links with PicOS and other neighbors."""

    def test_mikrotik_to_picos_bidirectional(self):
        """MikroTik sfp-sfpplus7 <-> PicOS te-1/1/1"""
        mikrotik_dev = make_device(
            "MikroTik", "10.17.70.50",
            sys_descr="MikroTik RouterOS 7.22beta6",
            vendor=DeviceVendor.MIKROTIK,
            neighbors=[
                make_lldp_neighbor("sfp-sfpplus7", "smf-core01-pica8", "te-1/1/1", None),
            ],
        )
        picos_dev = make_device(
            "smf-core01-pica8", "10.17.50.5",
            sys_descr="Pica8 PicOS 4.7.1M",
            vendor=DeviceVendor.PICA8,
            neighbors=[
                make_lldp_neighbor("te-1/1/1", "MikroTik", "sfp-sfpplus7", "10.17.70.50"),
            ],
        )
        topo = TopologyBuilder().build([mikrotik_dev, picos_dev])
        assert "MikroTik" in topo
        peers = topo["MikroTik"]["peers"]
        assert "smf-core01-pica8" in peers
        conns = peers["smf-core01-pica8"]["connections"]
        assert len(conns) == 1
        assert conns[0] == ["sfp-sfpplus7", "te-1/1/1"]

    def test_mikrotik_with_undiscovered_peer(self):
        """MikroTik sees a neighbor that wasn't discovered."""
        mikrotik_dev = make_device(
            "MikroTik", "10.17.70.50",
            sys_descr="MikroTik RouterOS 7.22",
            vendor=DeviceVendor.MIKROTIK,
            neighbors=[
                make_lldp_neighbor("ether1", "some-switch", "Gi0/1"),
            ],
        )
        topo = TopologyBuilder().build([mikrotik_dev])
        peers = topo["MikroTik"]["peers"]
        assert "some-switch" in peers

    def test_mikrotik_interface_normalization(self):
        """MikroTik sfp-sfpplusX and etherX pass through normalization."""
        assert normalize_interface("sfp-sfpplus7") == "sfp-sfpplus7"
        assert normalize_interface("ether1") == "ether1"
        assert normalize_interface("Portchannel1") == "Portchannel1"
