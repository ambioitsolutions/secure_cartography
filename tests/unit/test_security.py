"""
Tests for security-related modules: SSH host key policy, credential audit
logging, and security constants.

Covers:
- LoggingPolicy (ssh_policy.py): accepts unknown keys with warning logs.
- log_credential_access (audit_log.py): audit file creation and content.
- Security constants (constants.py): minimum safe values.
"""

import logging
import os
import stat
import sys
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure paramiko is importable even when the real package is not installed.
# ssh_policy.py does ``import paramiko`` and subclasses
# ``paramiko.MissingHostKeyPolicy``, so we inject a lightweight stub into
# sys.modules *before* importing the module under test.
# ---------------------------------------------------------------------------
if "paramiko" not in sys.modules:
    _paramiko_stub = MagicMock()

    # LoggingPolicy subclasses paramiko.MissingHostKeyPolicy.
    # The base class must be a real class (not a MagicMock) so that
    # ``class LoggingPolicy(paramiko.MissingHostKeyPolicy)`` works.
    class _MissingHostKeyPolicy:
        """Minimal stand-in for paramiko.MissingHostKeyPolicy."""
        def missing_host_key(self, client, hostname, key):
            raise Exception("Policy rejected the key")

    _paramiko_stub.MissingHostKeyPolicy = _MissingHostKeyPolicy
    sys.modules["paramiko"] = _paramiko_stub

from sc2.scng.ssh_policy import LoggingPolicy, get_ssh_policy
from sc2.scng.creds.audit_log import log_credential_access
from sc2.scng.constants import (
    MAX_UNLOCK_ATTEMPTS,
    MIN_PASSWORD_LENGTH,
    PBKDF2_ITERATIONS,
    SECURE_FILE_MODE,
    UNLOCK_LOCKOUT_SECONDS,
)


# ===========================================================================
# LoggingPolicy tests
# ===========================================================================

class TestLoggingPolicy:
    """Tests for the SSH host key logging policy."""

    def _make_mock_key(self, key_name="ssh-rsa", key_bytes=b"fake-key-bytes"):
        """Create a mock paramiko key object."""
        key = MagicMock()
        key.get_name.return_value = key_name
        key.asbytes.return_value = key_bytes
        return key

    def test_missing_host_key_does_not_raise(self):
        """missing_host_key should accept the key without raising."""
        policy = LoggingPolicy()
        client = MagicMock()
        key = self._make_mock_key()

        # Should complete without raising any exception
        policy.missing_host_key(client, "192.168.1.1", key)

    def test_missing_host_key_returns_none(self):
        """missing_host_key should return None (implicit accept)."""
        policy = LoggingPolicy()
        client = MagicMock()
        key = self._make_mock_key()

        result = policy.missing_host_key(client, "10.0.0.1", key)
        assert result is None

    def test_missing_host_key_logs_warning(self, caplog):
        """missing_host_key should emit a warning log with key details."""
        policy = LoggingPolicy()
        client = MagicMock()
        key = self._make_mock_key(key_name="ssh-ed25519", key_bytes=b"test-key")

        with caplog.at_level(logging.WARNING, logger="sc2.scng.ssh_policy"):
            policy.missing_host_key(client, "router1.lab.local", key)

        assert len(caplog.records) == 1
        record = caplog.records[0]
        assert record.levelno == logging.WARNING
        assert "ssh-ed25519" in record.message
        assert "router1.lab.local" in record.message
        assert "SHA256:" in record.message

    def test_missing_host_key_log_contains_fingerprint(self, caplog):
        """The logged message should contain the SHA-256 hex fingerprint."""
        import hashlib

        policy = LoggingPolicy()
        client = MagicMock()
        key_bytes = b"deterministic-key-material"
        key = self._make_mock_key(key_bytes=key_bytes)

        expected_fingerprint = hashlib.sha256(key_bytes).hexdigest()

        with caplog.at_level(logging.WARNING, logger="sc2.scng.ssh_policy"):
            policy.missing_host_key(client, "switch.example.com", key)

        assert expected_fingerprint in caplog.records[0].message

    def test_missing_host_key_calls_key_methods(self):
        """missing_host_key should call get_name() and asbytes() on the key."""
        policy = LoggingPolicy()
        client = MagicMock()
        key = self._make_mock_key()

        policy.missing_host_key(client, "10.0.0.1", key)

        key.get_name.assert_called_once()
        key.asbytes.assert_called_once()


class TestGetSshPolicy:
    """Tests for the get_ssh_policy factory function."""

    def test_returns_logging_policy_instance(self):
        """get_ssh_policy() should return a LoggingPolicy instance."""
        policy = get_ssh_policy()
        assert isinstance(policy, LoggingPolicy)

    def test_returns_new_instance_each_call(self):
        """Each call should return a distinct instance."""
        policy_a = get_ssh_policy()
        policy_b = get_ssh_policy()
        assert policy_a is not policy_b


# ===========================================================================
# Audit log tests
# ===========================================================================

class TestLogCredentialAccess:
    """Tests for the credential access audit logging."""

    @pytest.fixture(autouse=True)
    def _patch_audit_internals(self, tmp_path, monkeypatch):
        """Redirect the audit log to tmp_path and reset the handler."""
        import sc2.scng.creds.audit_log as audit_mod

        # Reset the global handler so _ensure_audit_handler re-initializes
        audit_mod._audit_handler = None

        # Point _AUDIT_DIR to a temp directory
        audit_dir = tmp_path / "audit"
        monkeypatch.setattr(audit_mod, "_AUDIT_DIR", audit_dir)

        # Remove any previously attached handlers from the logger to avoid
        # cross-test pollution
        audit_logger = logging.getLogger("sc2.audit.credentials")
        for handler in audit_logger.handlers[:]:
            audit_logger.removeHandler(handler)

        self.audit_dir = audit_dir
        self.audit_file = audit_dir / "credential_access.log"

        yield

        # Teardown: reset handler and clean up logger
        audit_mod._audit_handler = None
        audit_logger = logging.getLogger("sc2.audit.credentials")
        for handler in audit_logger.handlers[:]:
            audit_logger.removeHandler(handler)
            handler.close()

    def test_creates_audit_log_file(self):
        """Calling log_credential_access should create the audit log file."""
        assert not self.audit_file.exists()

        log_credential_access(operation="access", credential_name="test-cred")

        assert self.audit_file.exists()

    def test_creates_audit_directory(self):
        """The audit directory should be created if it does not exist."""
        assert not self.audit_dir.exists()

        log_credential_access(operation="list")

        assert self.audit_dir.is_dir()

    def test_log_entry_contains_operation(self):
        """Log entry should contain the operation field."""
        log_credential_access(operation="unlock")

        content = self.audit_file.read_text()
        assert "op=unlock" in content

    def test_log_entry_contains_credential_name(self):
        """Log entry should contain the credential name when provided."""
        log_credential_access(operation="access", credential_name="router-admin")

        content = self.audit_file.read_text()
        assert "cred=router-admin" in content

    def test_log_entry_contains_timestamp(self):
        """Log entries should begin with an ISO-8601 style timestamp."""
        log_credential_access(operation="test")

        content = self.audit_file.read_text()
        # The format is %Y-%m-%dT%H:%M:%S, so look for the T separator
        # between date and time components
        lines = [line for line in content.strip().splitlines() if line]
        assert len(lines) >= 1
        # Timestamp pattern: YYYY-MM-DDTHH:MM:SS
        first_line = lines[0]
        assert "T" in first_line[:20]
        # Check for date-like prefix (e.g., "2026-")
        assert first_line[:4].isdigit()
        assert first_line[4] == "-"

    def test_log_entry_contains_status_ok(self):
        """Successful operations should log status=OK."""
        log_credential_access(operation="add", success=True)

        content = self.audit_file.read_text()
        assert "status=OK" in content

    def test_log_entry_contains_status_fail(self):
        """Failed operations should log status=FAIL."""
        log_credential_access(operation="unlock", success=False)

        content = self.audit_file.read_text()
        assert "status=FAIL" in content

    def test_log_entry_contains_user(self):
        """Log entry should contain the current user."""
        log_credential_access(operation="list")

        content = self.audit_file.read_text()
        expected_user = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
        assert f"user={expected_user}" in content

    def test_log_entry_contains_credential_type(self):
        """Log entry should contain the credential type when provided."""
        log_credential_access(
            operation="add",
            credential_name="snmp-ro",
            credential_type="snmp_v2c",
        )

        content = self.audit_file.read_text()
        assert "type=snmp_v2c" in content

    def test_log_entry_contains_target_host(self):
        """Log entry should contain the target host when provided."""
        log_credential_access(
            operation="test",
            credential_name="admin-ssh",
            target_host="192.168.1.1",
        )

        content = self.audit_file.read_text()
        assert "target=192.168.1.1" in content

    def test_log_entry_contains_detail(self):
        """Log entry should contain extra detail when provided."""
        log_credential_access(
            operation="change_password",
            detail="vault migration",
        )

        content = self.audit_file.read_text()
        assert "detail=vault migration" in content

    def test_appends_multiple_entries(self):
        """Multiple calls should append to the same log file."""
        log_credential_access(operation="access", credential_name="cred-a")
        log_credential_access(operation="remove", credential_name="cred-b")
        log_credential_access(operation="list")

        content = self.audit_file.read_text()
        lines = [line for line in content.strip().splitlines() if line]
        assert len(lines) == 3
        assert "cred=cred-a" in lines[0]
        assert "cred=cred-b" in lines[1]
        assert "op=list" in lines[2]

    def test_omitted_optional_fields_absent(self):
        """Fields not provided should not appear in the log entry."""
        log_credential_access(operation="list")

        content = self.audit_file.read_text()
        assert "cred=" not in content
        assert "type=" not in content
        assert "target=" not in content
        assert "detail=" not in content

    @pytest.mark.skipif(
        os.name == "nt", reason="File permissions not applicable on Windows"
    )
    def test_log_file_permissions(self):
        """Audit log file should be set to 0o600 (owner read/write only)."""
        log_credential_access(operation="access")

        file_stat = os.stat(self.audit_file)
        file_mode = stat.S_IMODE(file_stat.st_mode)
        assert file_mode == 0o600


# ===========================================================================
# Security constants verification
# ===========================================================================

class TestSecurityConstants:
    """Verify security constants meet minimum safe thresholds."""

    def test_pbkdf2_iterations_minimum(self):
        """PBKDF2 iterations must be >= 600,000 (OWASP 2023 recommendation)."""
        assert PBKDF2_ITERATIONS >= 600_000

    def test_min_password_length(self):
        """Minimum password length must be >= 12 characters."""
        assert MIN_PASSWORD_LENGTH >= 12

    def test_max_unlock_attempts(self):
        """Max unlock attempts must be exactly 5."""
        assert MAX_UNLOCK_ATTEMPTS == 5

    def test_unlock_lockout_seconds(self):
        """Unlock lockout period must be exactly 300 seconds (5 minutes)."""
        assert UNLOCK_LOCKOUT_SECONDS == 300

    def test_secure_file_mode(self):
        """Secure file mode must be 0o600 (owner read/write only)."""
        assert SECURE_FILE_MODE == 0o600

    def test_secure_file_mode_no_group_or_other(self):
        """Secure file mode must not grant any group or other permissions."""
        assert SECURE_FILE_MODE & 0o077 == 0

    def test_pbkdf2_iterations_is_integer(self):
        """PBKDF2 iterations must be an integer (not a float)."""
        assert isinstance(PBKDF2_ITERATIONS, int)

    def test_lockout_seconds_is_positive(self):
        """Lockout duration must be a positive integer."""
        assert isinstance(UNLOCK_LOCKOUT_SECONDS, int)
        assert UNLOCK_LOCKOUT_SECONDS > 0
