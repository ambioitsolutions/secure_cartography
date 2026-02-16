"""
Unit tests for the SC2 export modules.

Tests cover:
- base.py: is_endpoint detection, Connection dataclass, preprocess_topology, MAC_PATTERN regex
- drawio_exporter.py: XML generation, device names in output, file writing
- graphml_exporter.py: XML generation, device names in output, file writing
- Both exporters: empty topology, single device with no peers
"""

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from sc2.export.base import (
    Connection,
    MAC_PATTERN,
    ENDPOINT_KEYWORDS,
    is_endpoint,
    preprocess_topology,
)
from sc2.export.drawio_exporter import DrawioExporter
from sc2.export.graphml_exporter import GraphMLExporter


# ---------------------------------------------------------------------------
# Helper: create a GraphMLExporter with resource lookups mocked out so tests
# do not require PyQt6 or real icon assets on disk.
# ---------------------------------------------------------------------------

def _make_graphml_exporter(**kwargs):
    """Instantiate GraphMLExporter while mocking resource helpers."""
    defaults = {"use_icons": False, "layout_type": "grid"}
    defaults.update(kwargs)
    with patch("sc2.export.graphml_exporter.get_resource_dir", return_value=Path("/tmp/fake_icons")), \
         patch("sc2.export.graphml_exporter.read_resource_text", side_effect=FileNotFoundError):
        return GraphMLExporter(**defaults)


# ============================================================================
# BaseExporter: is_endpoint
# ============================================================================

class TestIsEndpoint:
    """Tests for the is_endpoint() function."""

    def test_mac_address_dotted_format_is_endpoint(self):
        """A node whose ID is a dotted MAC address should be detected as an endpoint."""
        assert is_endpoint("aabb.ccdd.eeff", "") is True

    def test_mac_address_uppercase_is_endpoint(self):
        """MAC address detection should be case-insensitive."""
        assert is_endpoint("AABB.CCDD.EEFF", "") is True

    def test_mac_address_mixed_case_is_endpoint(self):
        assert is_endpoint("AaBb.CcDd.EeFf", "") is True

    def test_regular_hostname_is_not_endpoint(self):
        assert is_endpoint("core-switch", "Cisco IOS") is False

    def test_platform_keyword_endpoint(self):
        """Nodes whose platform string contains an endpoint keyword should be detected."""
        assert is_endpoint("device-1", "endpoint") is True

    def test_platform_keyword_camera(self):
        assert is_endpoint("cam-lobby", "IP Camera v2") is True

    def test_platform_keyword_phone(self):
        assert is_endpoint("phone-desk-42", "Cisco IP Phone 8845") is True

    def test_platform_keyword_printer(self):
        assert is_endpoint("hp-printer", "HP LaserJet Printer") is True

    def test_platform_keyword_pc(self):
        assert is_endpoint("user-pc", "pc workstation") is True

    def test_platform_keyword_workstation(self):
        assert is_endpoint("ws-01", "Dell Workstation") is True

    def test_platform_case_insensitive(self):
        """Platform keyword matching should be case-insensitive."""
        assert is_endpoint("device-1", "ENDPOINT DEVICE") is True

    def test_empty_platform_non_mac_is_not_endpoint(self):
        assert is_endpoint("switch-1", "") is False

    def test_none_platform_non_mac_is_not_endpoint(self):
        assert is_endpoint("switch-1", None) is False

    def test_switch_platform_is_not_endpoint(self):
        assert is_endpoint("sw-core", "Cisco Catalyst 9300") is False

    def test_router_platform_is_not_endpoint(self):
        """The router platform should not trigger endpoint detection (router is not in ENDPOINT_KEYWORDS)."""
        assert is_endpoint("rtr-1", "Cisco ISR 4331") is False

    def test_invalid_mac_too_short(self):
        """Partial MAC addresses should not match."""
        assert is_endpoint("aabb.ccdd", "SomeOS") is False

    def test_invalid_mac_wrong_delimiter(self):
        """Colon-delimited MAC addresses should not match the dotted pattern."""
        assert is_endpoint("aa:bb:cc:dd:ee:ff", "") is False


# ============================================================================
# BaseExporter: Connection dataclass
# ============================================================================

class TestConnection:
    """Tests for the Connection dataclass."""

    def test_creation(self):
        conn = Connection(local_port="Gi0/1", remote_port="Eth1")
        assert conn.local_port == "Gi0/1"
        assert conn.remote_port == "Eth1"

    def test_equality(self):
        conn_a = Connection("Gi0/1", "Eth1")
        conn_b = Connection("Gi0/1", "Eth1")
        assert conn_a == conn_b

    def test_inequality(self):
        conn_a = Connection("Gi0/1", "Eth1")
        conn_b = Connection("Gi0/1", "Eth2")
        assert conn_a != conn_b


# ============================================================================
# BaseExporter: MAC_PATTERN regex
# ============================================================================

class TestMacPattern:
    """Tests for the MAC_PATTERN compiled regex."""

    def test_valid_dotted_mac_lowercase(self):
        assert MAC_PATTERN.match("aabb.ccdd.eeff") is not None

    def test_valid_dotted_mac_uppercase(self):
        assert MAC_PATTERN.match("AABB.CCDD.EEFF") is not None

    def test_valid_dotted_mac_mixed(self):
        assert MAC_PATTERN.match("AaBb.CcDd.EeFf") is not None

    def test_all_zeros(self):
        assert MAC_PATTERN.match("0000.0000.0000") is not None

    def test_all_f(self):
        assert MAC_PATTERN.match("ffff.ffff.ffff") is not None

    def test_colon_delimited_does_not_match(self):
        assert MAC_PATTERN.match("aa:bb:cc:dd:ee:ff") is None

    def test_dash_delimited_does_not_match(self):
        assert MAC_PATTERN.match("aa-bb-cc-dd-ee-ff") is None

    def test_too_short(self):
        assert MAC_PATTERN.match("aabb.ccdd") is None

    def test_too_long(self):
        assert MAC_PATTERN.match("aabb.ccdd.eeff.0011") is None

    def test_non_hex_chars(self):
        assert MAC_PATTERN.match("gggg.hhhh.iiii") is None

    def test_no_dots(self):
        assert MAC_PATTERN.match("aabbccddeeff") is None

    def test_hostname_does_not_match(self):
        assert MAC_PATTERN.match("core-switch") is None


# ============================================================================
# BaseExporter: preprocess_topology
# ============================================================================

class TestPreprocessTopology:
    """Tests for the preprocess_topology() function."""

    def test_adds_undefined_peers(self, sample_topology):
        """Peers referenced but not defined should be added as endpoint entries."""
        # Add a reference to an undefined peer
        topo = sample_topology.copy()
        topo["core-switch"] = dict(topo["core-switch"])
        peers = dict(topo["core-switch"]["peers"])
        peers["unknown-device"] = {
            "ip": "10.0.99.1",
            "platform": "",
            "connections": [["Gi2/0/1", "eth0"]],
        }
        topo["core-switch"]["peers"] = peers

        result = preprocess_topology(topo)
        assert "unknown-device" in result
        assert result["unknown-device"]["node_details"]["platform"] == "endpoint"

    def test_preserves_defined_nodes(self, sample_topology):
        result = preprocess_topology(sample_topology)
        assert "core-switch" in result
        assert "dist-switch-1" in result
        assert "dist-switch-2" in result

    def test_filter_endpoints(self):
        """When include_endpoints=False, endpoint nodes should be removed."""
        topo = {
            "switch-1": {
                "node_details": {"ip": "10.0.0.1", "platform": "Cisco IOS"},
                "peers": {
                    "aabb.ccdd.eeff": {
                        "ip": "10.0.0.100",
                        "platform": "endpoint",
                        "connections": [["Gi0/1", "eth0"]],
                    }
                },
            },
        }
        result = preprocess_topology(topo, include_endpoints=False)
        assert "switch-1" in result
        assert "aabb.ccdd.eeff" not in result
        # The peer reference should also be removed from the peers dict
        assert "aabb.ccdd.eeff" not in result["switch-1"]["peers"]

    def test_connected_only_removes_standalone(self):
        """When connected_only=True, nodes with no connections should be removed."""
        topo = {
            "connected-sw": {
                "node_details": {"ip": "10.0.0.1", "platform": "Cisco IOS"},
                "peers": {
                    "other-sw": {
                        "ip": "10.0.0.2",
                        "platform": "Cisco IOS",
                        "connections": [["Gi0/1", "Gi0/1"]],
                    }
                },
            },
            "other-sw": {
                "node_details": {"ip": "10.0.0.2", "platform": "Cisco IOS"},
                "peers": {
                    "connected-sw": {
                        "ip": "10.0.0.1",
                        "platform": "Cisco IOS",
                        "connections": [["Gi0/1", "Gi0/1"]],
                    }
                },
            },
            "standalone-sw": {
                "node_details": {"ip": "10.0.0.3", "platform": "Cisco IOS"},
                "peers": {},
            },
        }
        result = preprocess_topology(topo, connected_only=True)
        assert "connected-sw" in result
        assert "other-sw" in result
        assert "standalone-sw" not in result

    def test_empty_topology(self):
        result = preprocess_topology({})
        assert result == {}

    def test_returns_copy_not_original(self, sample_topology):
        """preprocess_topology should return a copy, not mutate the original."""
        result = preprocess_topology(sample_topology)
        assert result is not sample_topology


# ============================================================================
# DrawioExporter
# ============================================================================

class TestDrawioExporter:
    """Tests for the DrawioExporter class."""

    @pytest.fixture
    def exporter(self):
        """Create a DrawioExporter with icons disabled to avoid filesystem lookups."""
        return DrawioExporter(use_icons=False, layout_type="grid")

    def test_export_produces_valid_xml(self, exporter, sample_topology, tmp_path):
        """Exporting a topology should produce a well-formed XML file."""
        output = tmp_path / "test_output.drawio"
        exporter.export(sample_topology, output)

        content = output.read_text(encoding="utf-8")
        # Should not raise an exception for well-formed XML
        root = ET.fromstring(content)
        assert root.tag == "mxfile"

    def test_output_contains_device_names(self, exporter, sample_topology, tmp_path):
        """The exported XML should reference all device names from the topology."""
        output = tmp_path / "topology.drawio"
        exporter.export(sample_topology, output)

        content = output.read_text(encoding="utf-8")
        assert "core-switch" in content
        assert "dist-switch-1" in content
        assert "dist-switch-2" in content

    def test_output_file_is_written(self, exporter, sample_topology, tmp_path):
        """The export method should create the output file on disk."""
        output = tmp_path / "output.drawio"
        assert not output.exists()
        exporter.export(sample_topology, output)
        assert output.exists()
        assert output.stat().st_size > 0

    def test_output_contains_mxgraphmodel(self, exporter, sample_topology, tmp_path):
        """The drawio XML should contain an mxGraphModel element."""
        output = tmp_path / "test.drawio"
        exporter.export(sample_topology, output)

        content = output.read_text(encoding="utf-8")
        root = ET.fromstring(content)
        model = root.find(".//mxGraphModel")
        assert model is not None

    def test_empty_topology(self, exporter, tmp_path):
        """Exporting an empty topology should still produce valid XML without errors."""
        output = tmp_path / "empty.drawio"
        exporter.export({}, output)

        content = output.read_text(encoding="utf-8")
        root = ET.fromstring(content)
        assert root.tag == "mxfile"

    def test_single_device_no_peers(self, exporter, tmp_path):
        """A topology with a single device and no peers should export successfully."""
        topo = {
            "lonely-switch": {
                "node_details": {"ip": "10.0.0.1", "platform": "Cisco IOS"},
                "peers": {},
            },
        }
        output = tmp_path / "single.drawio"
        exporter.export(topo, output)

        content = output.read_text(encoding="utf-8")
        assert "lonely-switch" in content
        root = ET.fromstring(content)
        assert root.tag == "mxfile"


# ============================================================================
# GraphMLExporter
# ============================================================================

class TestGraphMLExporter:
    """Tests for the GraphMLExporter class."""

    @pytest.fixture
    def exporter(self):
        """Create a GraphMLExporter with icons disabled and resource lookups mocked."""
        return _make_graphml_exporter()

    def test_export_produces_valid_xml(self, exporter, sample_topology, tmp_path):
        """Exporting a topology should produce a well-formed XML file."""
        output = tmp_path / "test_output.graphml"
        exporter.export(sample_topology, output)

        content = output.read_text(encoding="utf-8")
        root = ET.fromstring(content)
        assert root.tag == "{http://graphml.graphdrawing.org/xmlns}graphml"

    def test_output_contains_device_names(self, exporter, sample_topology, tmp_path):
        """The exported XML should reference all device names from the topology."""
        output = tmp_path / "topology.graphml"
        exporter.export(sample_topology, output)

        content = output.read_text(encoding="utf-8")
        assert "core-switch" in content
        assert "dist-switch-1" in content
        assert "dist-switch-2" in content

    def test_output_file_is_written(self, exporter, sample_topology, tmp_path):
        """The export method should create the output file on disk."""
        output = tmp_path / "output.graphml"
        assert not output.exists()
        exporter.export(sample_topology, output)
        assert output.exists()
        assert output.stat().st_size > 0

    def test_output_has_graph_element(self, exporter, sample_topology, tmp_path):
        """The GraphML XML should contain a graph element."""
        output = tmp_path / "test.graphml"
        exporter.export(sample_topology, output)

        content = output.read_text(encoding="utf-8")
        ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
        root = ET.fromstring(content)
        graph = root.find("g:graph", ns)
        assert graph is not None

    def test_empty_topology(self, exporter, tmp_path):
        """Exporting an empty topology should still produce valid XML without errors."""
        output = tmp_path / "empty.graphml"
        exporter.export({}, output)

        content = output.read_text(encoding="utf-8")
        root = ET.fromstring(content)
        assert root.tag == "{http://graphml.graphdrawing.org/xmlns}graphml"

    def test_single_device_no_peers(self, exporter, tmp_path):
        """A topology with a single device and no peers should export successfully."""
        topo = {
            "lonely-switch": {
                "node_details": {"ip": "10.0.0.1", "platform": "Cisco IOS"},
                "peers": {},
            },
        }
        output = tmp_path / "single.graphml"
        exporter.export(topo, output)

        content = output.read_text(encoding="utf-8")
        assert "lonely-switch" in content
        root = ET.fromstring(content)
        assert root.tag == "{http://graphml.graphdrawing.org/xmlns}graphml"


# ============================================================================
# Both Exporters: shared edge cases
# ============================================================================

class TestBothExportersEdgeCases:
    """Edge-case tests run against both DrawioExporter and GraphMLExporter."""

    @pytest.fixture(params=["drawio", "graphml"])
    def exporter_and_ext(self, request):
        """Parametrized fixture yielding (exporter_instance, file_extension)."""
        if request.param == "drawio":
            return DrawioExporter(use_icons=False, layout_type="grid"), ".drawio"
        else:
            return _make_graphml_exporter(), ".graphml"

    def test_empty_topology_produces_file(self, exporter_and_ext, tmp_path):
        """Both exporters should handle an empty topology without raising."""
        exporter, ext = exporter_and_ext
        output = tmp_path / f"empty{ext}"
        exporter.export({}, output)
        assert output.exists()
        assert output.stat().st_size > 0

    def test_single_device_no_peers_produces_file(self, exporter_and_ext, tmp_path):
        """Both exporters should handle a single device with no peers."""
        exporter, ext = exporter_and_ext
        topo = {
            "standalone-device": {
                "node_details": {"ip": "192.168.1.1", "platform": "Generic Switch"},
                "peers": {},
            },
        }
        output = tmp_path / f"single{ext}"
        exporter.export(topo, output)
        assert output.exists()

        content = output.read_text(encoding="utf-8")
        assert "standalone-device" in content

    def test_output_is_valid_xml(self, exporter_and_ext, sample_topology, tmp_path):
        """Both exporters should always produce well-formed XML."""
        exporter, ext = exporter_and_ext
        output = tmp_path / f"valid{ext}"
        exporter.export(sample_topology, output)

        content = output.read_text(encoding="utf-8")
        # ET.fromstring will raise ParseError for malformed XML
        ET.fromstring(content)
