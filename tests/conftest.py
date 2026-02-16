"""
Shared pytest fixtures for Secure Cartography tests.
"""

import json
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
from datetime import datetime

import pytest


# ---------------------------------------------------------------------------
# Vault / Encryption Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_vault(tmp_path):
    """Create a temporary vault with a known master password."""
    from sc2.scng.creds.vault import CredentialVault

    db_path = tmp_path / "test_vault.db"
    vault = CredentialVault(db_path=db_path)
    vault.initialize("TestPassword123!")
    return vault


@pytest.fixture
def locked_vault(tmp_path):
    """Create a temporary vault that is locked (initialized but not unlocked)."""
    from sc2.scng.creds.vault import CredentialVault

    db_path = tmp_path / "locked_vault.db"
    vault = CredentialVault(db_path=db_path)
    vault.initialize("TestPassword123!")
    vault.lock()
    return vault


# ---------------------------------------------------------------------------
# Device / Topology Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_device():
    """Create a sample Device for testing."""
    from sc2.scng.discovery.models import (
        Device, Interface, Neighbor, DeviceVendor,
        DiscoveryProtocol, NeighborProtocol, InterfaceStatus,
    )

    return Device(
        hostname="core-switch",
        ip_address="10.0.0.1",
        sys_name="core-switch.lab.local",
        sys_descr="Cisco IOS Software, Catalyst L3 Switch Software, Version 15.2(4)E10",
        vendor=DeviceVendor.CISCO,
        interfaces=[
            Interface(
                name="Gi0/1",
                if_index=1,
                status=InterfaceStatus.UP,
                speed_mbps=1000,
            ),
            Interface(
                name="Gi0/2",
                if_index=2,
                status=InterfaceStatus.UP,
                speed_mbps=1000,
            ),
        ],
        neighbors=[
            Neighbor.from_cdp(
                local_interface="Gi0/1",
                device_id="dist-switch-1",
                remote_port="Gi0/0",
                ip_address="10.0.1.1",
                platform="Arista DCS-7050",
            ),
            Neighbor.from_lldp(
                local_interface="Gi0/2",
                system_name="dist-switch-2",
                port_id="ge-0/0/0",
                management_address="10.0.2.1",
                system_description="Juniper Networks EX4300",
            ),
        ],
        arp_table={"aa:bb:cc:dd:ee:ff": "10.0.0.100"},
    )


@pytest.fixture
def sample_topology():
    """Create a sample topology dict (map.json format)."""
    return {
        "core-switch": {
            "node_details": {
                "ip": "10.0.0.1",
                "platform": "Cisco Catalyst 9300",
            },
            "peers": {
                "dist-switch-1": {
                    "ip": "10.0.1.1",
                    "platform": "Arista DCS-7050",
                    "connections": [["Gi1/0/1", "Eth1"]],
                },
                "dist-switch-2": {
                    "ip": "10.0.2.1",
                    "platform": "Juniper EX4300",
                    "connections": [["Gi1/0/2", "ge-0/0/0"]],
                },
            },
        },
        "dist-switch-1": {
            "node_details": {
                "ip": "10.0.1.1",
                "platform": "Arista DCS-7050",
            },
            "peers": {
                "core-switch": {
                    "ip": "10.0.0.1",
                    "platform": "Cisco Catalyst 9300",
                    "connections": [["Eth1", "Gi1/0/1"]],
                },
            },
        },
        "dist-switch-2": {
            "node_details": {
                "ip": "10.0.2.1",
                "platform": "Juniper EX4300",
            },
            "peers": {
                "core-switch": {
                    "ip": "10.0.0.1",
                    "platform": "Cisco Catalyst 9300",
                    "connections": [["ge-0/0/0", "Gi1/0/2"]],
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# SNMP / SSH Mocks
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_snmp_response():
    """Factory for mock SNMP responses."""
    def _make(sys_name="test-device", sys_descr="Cisco IOS", ip="10.0.0.1"):
        return {
            "sys_name": sys_name,
            "sys_descr": sys_descr,
            "sys_object_id": "1.3.6.1.4.1.9.1.1",
            "sys_location": "Lab",
            "sys_contact": "admin@example.com",
            "ip_address": ip,
        }
    return _make


@pytest.fixture
def mock_ssh_client():
    """Create a mock paramiko SSHClient."""
    client = MagicMock()
    channel = MagicMock()
    channel.recv_ready.return_value = True
    channel.recv.return_value = b"hostname#"
    client.invoke_shell.return_value = channel

    transport = MagicMock()
    transport.is_active.return_value = True
    client.get_transport.return_value = transport

    return client
