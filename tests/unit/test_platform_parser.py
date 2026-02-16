"""
Tests for PlatformParser - vendor/product/version extraction and CPE generation.

Covers ParsedPlatform.to_cpe, PlatformParser.parse with known vendor patterns,
generic fallback parsing, empty input handling, custom pattern support, and
Cisco version normalization.
"""

import json
import sys
from unittest.mock import MagicMock

import pytest

# platform_parser.py is pure stdlib, but its package path traverses sc2.ui
# which eagerly imports PyQt6.  Inject lightweight mocks so the import chain
# succeeds in headless / CI environments where PyQt6 is not installed.
if "PyQt6" not in sys.modules:
    _qt = MagicMock()
    for _mod in (
        "PyQt6", "PyQt6.QtCore", "PyQt6.QtGui", "PyQt6.QtWidgets",
        "PyQt6.QtWebEngineCore", "PyQt6.QtWebEngineWidgets",
        "PyQt6.QtWebChannel", "PyQt6.QtNetwork", "PyQt6.sip",
    ):
        sys.modules.setdefault(_mod, _qt)

from sc2.ui.widgets.security.platform_parser import ParsedPlatform, PlatformParser


# ---------------------------------------------------------------------------
# ParsedPlatform.to_cpe
# ---------------------------------------------------------------------------

class TestParsedPlatformToCpe:
    """Test CPE 2.3 string generation from ParsedPlatform."""

    def test_generates_correct_cpe_string(self):
        pp = ParsedPlatform(
            raw="Juniper JUNOS 14.1X53-D40.8",
            vendor="Juniper",
            product="JUNOS",
            version="14.1X53-D40.8",
            cpe_vendor="juniper",
            cpe_product="junos",
            cpe_version="14.1x53-d40.8",
            confidence="high",
        )
        assert pp.to_cpe() == "cpe:2.3:o:juniper:junos:14.1x53-d40.8:*:*:*:*:*:*:*"

    def test_returns_empty_when_cpe_vendor_missing(self):
        pp = ParsedPlatform(
            raw="something", vendor="V", product="P", version="1.0",
            cpe_vendor="", cpe_product="prod", cpe_version="1.0",
            confidence="low",
        )
        assert pp.to_cpe() == ""

    def test_returns_empty_when_cpe_product_missing(self):
        pp = ParsedPlatform(
            raw="something", vendor="V", product="P", version="1.0",
            cpe_vendor="vendor", cpe_product="", cpe_version="1.0",
            confidence="low",
        )
        assert pp.to_cpe() == ""

    def test_returns_empty_when_cpe_version_missing(self):
        pp = ParsedPlatform(
            raw="something", vendor="V", product="P", version="1.0",
            cpe_vendor="vendor", cpe_product="prod", cpe_version="",
            confidence="low",
        )
        assert pp.to_cpe() == ""

    def test_returns_empty_when_all_cpe_fields_missing(self):
        pp = ParsedPlatform(
            raw="unknown", vendor="", product="", version="",
            cpe_vendor="", cpe_product="", cpe_version="",
            confidence="low",
        )
        assert pp.to_cpe() == ""

    def test_cpe_with_cisco_escaped_version(self):
        pp = ParsedPlatform(
            raw="Cisco IOS 15.6(2)T",
            vendor="Cisco", product="IOS", version="15.6(2)T",
            cpe_vendor="cisco", cpe_product="ios", cpe_version="15.6\\(2\\)t",
            confidence="high",
        )
        expected = "cpe:2.3:o:cisco:ios:15.6\\(2\\)t:*:*:*:*:*:*:*"
        assert pp.to_cpe() == expected


# ---------------------------------------------------------------------------
# PlatformParser.parse - known vendor patterns
# ---------------------------------------------------------------------------

class TestParseKnownPlatforms:
    """Test parse() against known vendor platform strings."""

    def setup_method(self, tmp_path=None):
        # Use a non-existent path to avoid loading any custom patterns
        from pathlib import Path
        self.parser = PlatformParser(
            custom_patterns_path=Path("/tmp/_test_no_patterns_exist_.json")
        )

    # -- Juniper --------------------------------------------------------

    def test_juniper_junos(self):
        result = self.parser.parse("Juniper JUNOS 14.1X53-D40.8")
        assert result.vendor == "Juniper"
        assert result.product == "JUNOS"
        assert result.version == "14.1X53-D40.8"
        assert result.cpe_vendor == "juniper"
        assert result.cpe_product == "junos"
        assert result.confidence == "high"

    def test_juniper_junos_version_in_cpe(self):
        result = self.parser.parse("Juniper JUNOS 14.1X53-D40.8")
        assert result.cpe_version == "14.1x53-d40.8"

    def test_juniper_junos_bare(self):
        result = self.parser.parse("JUNOS 22.3R1.11")
        assert result.vendor == "Juniper"
        assert result.product == "JUNOS"
        assert result.version == "22.3R1.11"
        assert result.confidence == "high"

    # -- Arista ---------------------------------------------------------

    def test_arista_veos_lab(self):
        result = self.parser.parse("Arista vEOS-lab EOS 4.23.3M")
        assert result.vendor == "Arista"
        assert result.product == "EOS"
        assert result.version == "4.23.3M"
        assert result.cpe_vendor == "arista"
        assert result.cpe_product == "eos"
        assert result.confidence == "high"

    def test_arista_eos_plain(self):
        result = self.parser.parse("Arista EOS 4.20.15M")
        assert result.vendor == "Arista"
        assert result.product == "EOS"
        assert result.version == "4.20.15M"

    def test_arista_networks_eos(self):
        result = self.parser.parse("Arista Networks EOS 4.33.1F")
        assert result.vendor == "Arista"
        assert result.product == "EOS"
        assert result.version == "4.33.1F"

    # -- Cisco IOS ------------------------------------------------------

    def test_cisco_ios(self):
        result = self.parser.parse("Cisco IOS 15.6(2)T")
        assert result.vendor == "Cisco"
        assert result.product == "IOS"
        assert result.version == "15.6(2)T"
        assert result.cpe_vendor == "cisco"
        assert result.cpe_product == "ios"
        assert result.confidence == "high"

    def test_cisco_ios_version_normalized(self):
        """Cisco parentheses should be escaped in CPE version."""
        result = self.parser.parse("Cisco IOS 15.6(2)T")
        assert "\\(" in result.cpe_version
        assert "\\)" in result.cpe_version

    def test_cisco_ios_complex_version(self):
        result = self.parser.parse("Cisco IOS 12.2(54)SG1")
        assert result.vendor == "Cisco"
        assert result.product == "IOS"
        assert result.version == "12.2(54)SG1"

    # -- Cisco IOS-XE ---------------------------------------------------

    def test_cisco_ios_xe(self):
        result = self.parser.parse("Cisco IOS-XE Software, Version 16.12.4")
        assert result.vendor == "Cisco"
        assert result.product == "IOS-XE"
        assert result.version == "16.12.4"
        assert result.cpe_vendor == "cisco"
        assert result.cpe_product == "ios_xe"
        assert result.confidence == "high"

    def test_cisco_ios_xe_alternate_spacing(self):
        result = self.parser.parse("Cisco IOS XE Software, Version 17.3.1")
        assert result.vendor == "Cisco"
        assert result.product == "IOS-XE"
        assert result.version == "17.3.1"

    # -- Cisco NX-OS ----------------------------------------------------

    def test_cisco_nxos(self):
        result = self.parser.parse("Cisco NX-OS Version 9.3(3)")
        assert result.vendor == "Cisco"
        assert result.product == "NX-OS"
        assert result.version == "9.3(3)"
        assert result.cpe_vendor == "cisco"
        assert result.cpe_product == "nx-os"
        assert result.confidence == "high"

    def test_cisco_nxos_version_normalized(self):
        result = self.parser.parse("Cisco NX-OS Version 9.3(3)")
        assert result.cpe_version == "9.3\\(3\\)"

    # -- Palo Alto PAN-OS -----------------------------------------------

    def test_palo_alto(self):
        result = self.parser.parse("Palo Alto Networks PAN-OS 10.1.3")
        assert result.vendor == "Palo Alto"
        assert result.product == "PAN-OS"
        assert result.version == "10.1.3"
        assert result.cpe_vendor == "paloaltonetworks"
        assert result.cpe_product == "pan-os"
        assert result.confidence == "high"

    def test_palo_alto_bare(self):
        result = self.parser.parse("PAN-OS 9.1.0")
        assert result.vendor == "Palo Alto"
        assert result.product == "PAN-OS"
        assert result.version == "9.1.0"

    # -- Fortinet FortiOS ------------------------------------------------

    def test_fortios_with_v_prefix(self):
        result = self.parser.parse("FortiOS v7.0.5")
        assert result.vendor == "Fortinet"
        assert result.product == "FortiOS"
        assert result.version == "7.0.5"
        assert result.cpe_vendor == "fortinet"
        assert result.cpe_product == "fortios"
        assert result.confidence == "high"

    def test_fortios_full_prefix(self):
        result = self.parser.parse("Fortinet FortiOS 6.4.9")
        assert result.vendor == "Fortinet"
        assert result.product == "FortiOS"
        assert result.version == "6.4.9"

    def test_fortios_uppercase_v(self):
        result = self.parser.parse("FortiOS V7.2.1")
        assert result.vendor == "Fortinet"
        assert result.version == "7.2.1"


# ---------------------------------------------------------------------------
# PlatformParser.parse - generic fallback
# ---------------------------------------------------------------------------

class TestParseGenericFallback:
    """Test parse() with unrecognized platform strings."""

    def setup_method(self):
        from pathlib import Path
        self.parser = PlatformParser(
            custom_patterns_path=Path("/tmp/_test_no_patterns_exist_.json")
        )

    def test_unknown_platform_low_confidence(self):
        result = self.parser.parse("SomeVendor Widget OS 3.2.1")
        assert result.confidence == "low"

    def test_unknown_platform_extracts_version(self):
        result = self.parser.parse("SomeVendor Widget OS 3.2.1")
        assert result.version == "3.2.1"

    def test_unknown_platform_empty_cpe_fields(self):
        result = self.parser.parse("SomeVendor Widget OS 3.2.1")
        assert result.cpe_vendor == ""
        assert result.cpe_product == ""
        assert result.cpe_version == ""

    def test_unknown_platform_no_version(self):
        result = self.parser.parse("mystery box with no numbers")
        assert result.confidence == "low"
        assert result.version == ""

    def test_generic_detects_known_vendor_keyword(self):
        """Fallback still identifies vendor from keyword even if pattern fails."""
        result = self.parser.parse("Dell something unusual format")
        assert result.vendor == "Dell"
        assert result.confidence == "low"

    def test_generic_preserves_raw(self):
        raw = "CompletelyUnknown Platform XYZ"
        result = self.parser.parse(raw)
        assert result.raw == raw


# ---------------------------------------------------------------------------
# PlatformParser.parse - empty string
# ---------------------------------------------------------------------------

class TestParseEmptyInput:
    """Test parse() with empty or falsy input."""

    def setup_method(self):
        from pathlib import Path
        self.parser = PlatformParser(
            custom_patterns_path=Path("/tmp/_test_no_patterns_exist_.json")
        )

    def test_empty_string_returns_low_confidence(self):
        result = self.parser.parse("")
        assert result.confidence == "low"

    def test_empty_string_returns_empty_fields(self):
        result = self.parser.parse("")
        assert result.vendor == ""
        assert result.product == ""
        assert result.version == ""
        assert result.cpe_vendor == ""
        assert result.cpe_product == ""
        assert result.cpe_version == ""

    def test_empty_string_raw_is_empty(self):
        result = self.parser.parse("")
        assert result.raw == ""

    def test_empty_string_cpe_is_empty(self):
        result = self.parser.parse("")
        assert result.to_cpe() == ""


# ---------------------------------------------------------------------------
# Custom patterns via save_custom_pattern
# ---------------------------------------------------------------------------

class TestCustomPatterns:
    """Test save_custom_pattern and custom pattern priority."""

    def test_save_and_load_custom_pattern(self, tmp_path):
        patterns_file = tmp_path / "patterns.json"
        parser = PlatformParser(custom_patterns_path=patterns_file)

        parser.save_custom_pattern(
            regex=r"MyVendor\s+MyOS\s+(\d+\.\d+\.\d+)",
            vendor="MyVendor",
            product="MyOS",
            cpe_vendor="myvendor",
            cpe_product="myos",
        )

        result = parser.parse("MyVendor MyOS 2.5.1")
        assert result.vendor == "MyVendor"
        assert result.product == "MyOS"
        assert result.version == "2.5.1"
        assert result.confidence == "high"

    def test_custom_pattern_persisted_to_file(self, tmp_path):
        patterns_file = tmp_path / "patterns.json"
        parser = PlatformParser(custom_patterns_path=patterns_file)

        parser.save_custom_pattern(
            regex=r"TestBox\s+v(\d+\.\d+)",
            vendor="TestCorp",
            product="TestBox",
            cpe_vendor="testcorp",
            cpe_product="testbox",
        )

        assert patterns_file.exists()
        data = json.loads(patterns_file.read_text())
        assert len(data) == 1
        assert data[0]["vendor"] == "TestCorp"

    def test_custom_pattern_loaded_by_new_parser(self, tmp_path):
        patterns_file = tmp_path / "patterns.json"

        # First parser saves a pattern
        parser1 = PlatformParser(custom_patterns_path=patterns_file)
        parser1.save_custom_pattern(
            regex=r"SpecialOS\s+(\d+\.\d+\.\d+)",
            vendor="SpecialVendor",
            product="SpecialOS",
            cpe_vendor="specialvendor",
            cpe_product="specialos",
        )

        # Second parser loads from the same file
        parser2 = PlatformParser(custom_patterns_path=patterns_file)
        result = parser2.parse("SpecialOS 8.1.0")
        assert result.vendor == "SpecialVendor"
        assert result.product == "SpecialOS"
        assert result.version == "8.1.0"
        assert result.confidence == "high"

    def test_custom_pattern_takes_priority_over_default(self, tmp_path):
        """Custom patterns are inserted at the front and override defaults."""
        patterns_file = tmp_path / "patterns.json"
        parser = PlatformParser(custom_patterns_path=patterns_file)

        # Override Juniper detection with a custom pattern that reports
        # a different vendor/product.
        parser.save_custom_pattern(
            regex=r"Juniper\s+JUNOS?\s+(\d+\.\d+[A-Z0-9\-\.]+)",
            vendor="CustomJuniper",
            product="CustomJUNOS",
            cpe_vendor="customjuniper",
            cpe_product="customjunos",
        )

        result = parser.parse("Juniper JUNOS 14.1X53-D40.8")
        assert result.vendor == "CustomJuniper"
        assert result.product == "CustomJUNOS"
        assert result.cpe_vendor == "customjuniper"

    def test_multiple_custom_patterns(self, tmp_path):
        patterns_file = tmp_path / "patterns.json"
        parser = PlatformParser(custom_patterns_path=patterns_file)

        parser.save_custom_pattern(
            regex=r"AlphaOS\s+(\d+\.\d+)",
            vendor="Alpha", product="AlphaOS",
            cpe_vendor="alpha", cpe_product="alphaos",
        )
        parser.save_custom_pattern(
            regex=r"BetaOS\s+(\d+\.\d+)",
            vendor="Beta", product="BetaOS",
            cpe_vendor="beta", cpe_product="betaos",
        )

        assert parser.parse("AlphaOS 1.0").vendor == "Alpha"
        assert parser.parse("BetaOS 2.0").vendor == "Beta"

    def test_creates_parent_directories(self, tmp_path):
        patterns_file = tmp_path / "subdir" / "deep" / "patterns.json"
        parser = PlatformParser(custom_patterns_path=patterns_file)

        parser.save_custom_pattern(
            regex=r"Foo\s+(\d+)",
            vendor="Foo", product="FooOS",
            cpe_vendor="foo", cpe_product="fooos",
        )

        assert patterns_file.exists()


# ---------------------------------------------------------------------------
# _normalize_version
# ---------------------------------------------------------------------------

class TestNormalizeVersion:
    """Test version normalization rules."""

    def setup_method(self):
        from pathlib import Path
        self.parser = PlatformParser(
            custom_patterns_path=Path("/tmp/_test_no_patterns_exist_.json")
        )

    def test_cisco_parentheses_escaped(self):
        result = self.parser._normalize_version("cisco", "15.6(2)T")
        assert result == "15.6\\(2\\)t"

    def test_cisco_multiple_parentheses(self):
        result = self.parser._normalize_version("cisco", "12.2(54)SG1")
        assert result == "12.2\\(54\\)sg1"

    def test_cisco_lowercased(self):
        result = self.parser._normalize_version("cisco", "9.3(3)")
        assert result == "9.3\\(3\\)"

    def test_non_cisco_passthrough(self):
        result = self.parser._normalize_version("juniper", "14.1X53-D40.8")
        assert result == "14.1x53-d40.8"

    def test_non_cisco_no_escape(self):
        """Non-Cisco vendors should not have parentheses escaped."""
        result = self.parser._normalize_version("arista", "4.23(1)M")
        assert "\\(" not in result
        assert result == "4.23(1)m"

    def test_version_lowercased_for_all_vendors(self):
        result = self.parser._normalize_version("paloaltonetworks", "10.1.3-H1")
        assert result == "10.1.3-h1"

    def test_version_stripped(self):
        result = self.parser._normalize_version("juniper", "  22.3R1.11  ")
        assert result == "22.3r1.11"


# ---------------------------------------------------------------------------
# Integration: parse -> to_cpe round-trip
# ---------------------------------------------------------------------------

class TestParseToCpeRoundTrip:
    """Verify parse output feeds correctly into to_cpe."""

    def setup_method(self):
        from pathlib import Path
        self.parser = PlatformParser(
            custom_patterns_path=Path("/tmp/_test_no_patterns_exist_.json")
        )

    def test_juniper_cpe_roundtrip(self):
        result = self.parser.parse("Juniper JUNOS 14.1X53-D40.8")
        cpe = result.to_cpe()
        assert cpe == "cpe:2.3:o:juniper:junos:14.1x53-d40.8:*:*:*:*:*:*:*"

    def test_cisco_ios_cpe_roundtrip(self):
        result = self.parser.parse("Cisco IOS 15.6(2)T")
        cpe = result.to_cpe()
        assert cpe == "cpe:2.3:o:cisco:ios:15.6\\(2\\)t:*:*:*:*:*:*:*"

    def test_arista_cpe_roundtrip(self):
        result = self.parser.parse("Arista vEOS-lab EOS 4.23.3M")
        cpe = result.to_cpe()
        assert cpe == "cpe:2.3:o:arista:eos:4.23.3m:*:*:*:*:*:*:*"

    def test_palo_alto_cpe_roundtrip(self):
        result = self.parser.parse("Palo Alto Networks PAN-OS 10.1.3")
        cpe = result.to_cpe()
        assert cpe == "cpe:2.3:o:paloaltonetworks:pan-os:10.1.3:*:*:*:*:*:*:*"

    def test_generic_fallback_cpe_empty(self):
        result = self.parser.parse("Unknown thing 1.2.3")
        assert result.to_cpe() == ""
