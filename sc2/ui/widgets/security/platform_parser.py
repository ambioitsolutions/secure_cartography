"""
Secure Cartography - Platform Parser.

Extensible parser for network device platform strings.
Extracts vendor, product, and version for CPE matching.
"""

import re
import json
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ParsedPlatform:
    """Result of parsing a platform string"""
    raw: str
    vendor: str
    product: str
    version: str
    cpe_vendor: str
    cpe_product: str
    cpe_version: str
    confidence: str  # high, medium, low, manual
    device_count: int = 1
    device_names: list = field(default_factory=list)

    def to_cpe(self) -> str:
        """Generate CPE 2.3 string"""
        if not all([self.cpe_vendor, self.cpe_product, self.cpe_version]):
            return ""
        return f"cpe:2.3:o:{self.cpe_vendor}:{self.cpe_product}:{self.cpe_version}:*:*:*:*:*:*:*"


class PlatformParser:
    """
    Extensible parser for network device platform strings.

    Extracts vendor, product, and version from strings like:
        "Juniper JUNOS 14.1X53-D40.8"
        "Cisco IOS 12.2(54)SG1"
        "Arista EOS 4.23.3M"

    Users can add custom patterns via add_pattern() or patterns.json
    """

    DEFAULT_PATTERNS = [
        # Juniper
        (r"Juniper\s+JUNOS?\s+(?:OS\s+)?(\d+\.\d+[A-Z0-9\-\.]+)",
         "Juniper", "JUNOS", "juniper", "junos", 1),
        (r"JUNOS\s+(\d+\.\d+[A-Z0-9\-\.]+)",
         "Juniper", "JUNOS", "juniper", "junos", 1),

        # Arista EOS
        (r"Arista\s+(?:vEOS[^\s]*\s+)?EOS\s+(\d+\.\d+\.\d+[A-Z]*)",
         "Arista", "EOS", "arista", "eos", 1),
        (r"Arista\s+Networks?\s+(?:vEOS[^\s]*\s+)?EOS\s+(\d+\.\d+\.\d+[A-Z]*)",
         "Arista", "EOS", "arista", "eos", 1),
        (r"vEOS[^\s]*\s+EOS\s+(\d+\.\d+\.\d+[A-Z]*)",
         "Arista", "EOS", "arista", "eos", 1),

        # Cisco IOS
        (r"Cisco\s+(?:IOS[v]?\s+)?(?:IOS\s+)?(\d+\.\d+\([0-9\.]+\)[A-Za-z0-9]*)",
         "Cisco", "IOS", "cisco", "ios", 1),
        (r"Cisco\s+\d+\s+IOS\s+(\d+\.\d+\([0-9\.]+\)[A-Za-z0-9]*)",
         "Cisco", "IOS", "cisco", "ios", 1),
        (r"Cisco\s+IOSv\s+IOS\s+(\d+\.\d+\([0-9\.]+\)[A-Za-z0-9]*)",
         "Cisco", "IOS", "cisco", "ios", 1),

        # Cisco IOS-XE / IOS-XR / NX-OS
        (r"Cisco\s+IOS[- ]?XE\s+[Ss]oftware[,\s]+Version\s+(\d+\.\d+\.\d+[A-Za-z0-9\.]*)",
         "Cisco", "IOS-XE", "cisco", "ios_xe", 1),
        (r"Cisco\s+IOS[- ]?XR\s+[Ss]oftware[,\s]+Version\s+(\d+\.\d+\.\d+[A-Za-z0-9\.]*)",
         "Cisco", "IOS-XR", "cisco", "ios_xr", 1),
        (r"Cisco\s+NX-?OS.*Version\s+(\d+\.\d+\([0-9]+\)[A-Za-z0-9\.]*)",
         "Cisco", "NX-OS", "cisco", "nx-os", 1),
        (r"Cisco\s+IOS\s+(?:Software,?\s+)?(?:Version\s+)?(\d+\.\d+\([0-9]+\)[A-Za-z0-9]*)",
         "Cisco", "IOS", "cisco", "ios", 1),

        # Fallback Cisco
        (r"[Cc]isco.*IOS.*?(\d+\.\d+\([0-9\.]+\)[A-Za-z0-9]*)",
         "Cisco", "IOS", "cisco", "ios", 1),

        # Palo Alto PAN-OS
        (r"Palo\s+Alto\s+Networks?\s+PAN-?OS\s+(\d+\.\d+\.\d+[A-Za-z0-9\-]*)",
         "Palo Alto", "PAN-OS", "paloaltonetworks", "pan-os", 1),
        (r"PAN-?OS\s+(\d+\.\d+\.\d+[A-Za-z0-9\-]*)",
         "Palo Alto", "PAN-OS", "paloaltonetworks", "pan-os", 1),

        # Fortinet FortiOS
        (r"Fortinet\s+FortiOS\s+[vV]?(\d+\.\d+\.\d+[A-Za-z0-9\-]*)",
         "Fortinet", "FortiOS", "fortinet", "fortios", 1),
        (r"FortiOS\s+[vV]?(\d+\.\d+\.\d+[A-Za-z0-9\-]*)",
         "Fortinet", "FortiOS", "fortinet", "fortios", 1),
        (r"FortiGate.*[vV](\d+\.\d+\.\d+)",
         "Fortinet", "FortiOS", "fortinet", "fortios", 1),

        # F5 BIG-IP
        (r"BIG-?IP.*(\d+\.\d+\.\d+[A-Za-z0-9\.]*)",
         "F5", "BIG-IP", "f5", "big-ip_access_policy_manager", 1),

        # HPE/Aruba
        (r"ArubaOS[- ]?(?:CX)?[- ]?(\d+\.\d+\.\d+[A-Za-z0-9\.]*)",
         "Aruba", "ArubaOS", "arubanetworks", "arubaos", 1),
        (r"HPE?\s+(?:ProCurve|Comware).*Version\s+(\d+\.\d+[A-Za-z0-9\.]*)",
         "HPE", "Comware", "hp", "comware", 1),

        # Dell / Force10
        (r"Dell\s+(?:Networking\s+)?OS[0-9]*\s+(\d+\.\d+\.\d+[A-Za-z0-9\.]*)",
         "Dell", "OS10", "dell", "os10", 1),

        # Brocade / Ruckus
        (r"Brocade.*FOS\s+[vV]?(\d+\.\d+\.\d+[A-Za-z0-9]*)",
         "Brocade", "FOS", "brocade", "fabric_os", 1),

        # Extreme Networks
        (r"Extreme(?:XOS|Ware)?\s+(\d+\.\d+\.\d+[A-Za-z0-9\.]*)",
         "Extreme", "ExtremeXOS", "extremenetworks", "extremexos", 1),

        # MikroTik RouterOS
        (r"(?:MikroTik\s+)?RouterOS\s+(\d+\.\d+[A-Za-z0-9\.]*)",
         "MikroTik", "RouterOS", "mikrotik", "routeros", 1),

        # Ubiquiti
        (r"Ubiquiti.*EdgeOS\s+[vV]?(\d+\.\d+\.\d+)",
         "Ubiquiti", "EdgeOS", "ubiquiti", "edgeos", 1),
        (r"UniFi.*(\d+\.\d+\.\d+)",
         "Ubiquiti", "UniFi", "ubiquiti", "unifi_controller", 1),
    ]

    def __init__(self, custom_patterns_path: Optional[Path] = None):
        self.patterns = list(self.DEFAULT_PATTERNS)
        self.custom_patterns_path = custom_patterns_path or Path.home() / ".scng" / "platform_patterns.json"
        self._load_custom_patterns()

    def _load_custom_patterns(self):
        """Load user-defined patterns from JSON file"""
        if self.custom_patterns_path.exists():
            try:
                with open(self.custom_patterns_path) as f:
                    custom = json.load(f)
                for p in custom:
                    self.patterns.insert(0, (
                        p["regex"],
                        p["vendor"],
                        p["product"],
                        p["cpe_vendor"],
                        p["cpe_product"],
                        p.get("version_group", 1)
                    ))
                logger.info(f"Loaded {len(custom)} custom patterns")
            except Exception as e:
                logger.warning(f"Could not load custom patterns: {e}")

    def save_custom_pattern(self, regex: str, vendor: str, product: str,
                            cpe_vendor: str, cpe_product: str):
        """Save a new custom pattern"""
        self.custom_patterns_path.parent.mkdir(parents=True, exist_ok=True)

        existing = []
        if self.custom_patterns_path.exists():
            with open(self.custom_patterns_path) as f:
                existing = json.load(f)

        existing.append({
            "regex": regex,
            "vendor": vendor,
            "product": product,
            "cpe_vendor": cpe_vendor,
            "cpe_product": cpe_product,
            "version_group": 1
        })

        with open(self.custom_patterns_path, "w") as f:
            json.dump(existing, f, indent=2)

        self.patterns.insert(0, (regex, vendor, product, cpe_vendor, cpe_product, 1))

    def parse(self, platform_string: str) -> ParsedPlatform:
        """Parse a platform string and extract vendor/product/version"""
        if not platform_string:
            return ParsedPlatform(
                raw=platform_string, vendor="", product="", version="",
                cpe_vendor="", cpe_product="", cpe_version="",
                confidence="low"
            )

        for pattern, vendor, product, cpe_vendor, cpe_product, ver_group in self.patterns:
            match = re.search(pattern, platform_string, re.IGNORECASE)
            if match:
                version = match.group(ver_group)
                cpe_version = self._normalize_version(cpe_vendor, version)

                return ParsedPlatform(
                    raw=platform_string,
                    vendor=vendor,
                    product=product,
                    version=version,
                    cpe_vendor=cpe_vendor,
                    cpe_product=cpe_product,
                    cpe_version=cpe_version,
                    confidence="high"
                )

        return self._generic_parse(platform_string)

    def _generic_parse(self, platform_string: str) -> ParsedPlatform:
        """Fallback parser for unrecognized platforms"""
        version_match = re.search(r'(\d+\.\d+[\.\d]*[A-Za-z0-9\-\(\)]*)', platform_string)
        version = version_match.group(1) if version_match else ""

        vendor = ""
        for keyword in ["Cisco", "Juniper", "Arista", "Palo Alto", "Fortinet",
                        "F5", "HPE", "Dell", "Brocade", "Extreme", "MikroTik"]:
            if keyword.lower() in platform_string.lower():
                vendor = keyword
                break

        return ParsedPlatform(
            raw=platform_string,
            vendor=vendor,
            product="",
            version=version,
            cpe_vendor="",
            cpe_product="",
            cpe_version="",
            confidence="low"
        )

    def _normalize_version(self, vendor: str, version: str) -> str:
        """Normalize version string for CPE format"""
        v = version.lower().strip()
        if vendor == "cisco":
            v = v.replace("(", "\\(").replace(")", "\\)")
        return v
