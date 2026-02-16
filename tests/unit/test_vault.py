"""
Unit tests for CredentialVault (sc2.scng.creds.vault).

Tests cover vault lifecycle, credential CRUD for all types,
rate limiting, locking behavior, password changes, and defaults.
"""

import time
from unittest.mock import patch

import pytest

from sc2.scng.creds.vault import (
    CredentialVault,
    VaultError,
    VaultNotInitialized,
    CredentialNotFound,
    DuplicateCredential,
    VaultLockedOut,
)
from sc2.scng.creds.encryption import VaultLocked, InvalidPassword
from sc2.scng.creds.models import (
    CredentialType,
    SSHCredential,
    SNMPv2cCredential,
    SNMPv3Credential,
    SNMPv3AuthProtocol,
    SNMPv3PrivProtocol,
)
from sc2.scng.constants import MAX_UNLOCK_ATTEMPTS, UNLOCK_LOCKOUT_SECONDS

TEST_PASSWORD = "TestPassword123!"


# =============================================================================
# 1. Initialization
# =============================================================================

class TestInitialize:
    """Vault initialization creates the DB and leaves vault unlocked."""

    def test_initialize_creates_db(self, tmp_path):
        db_path = tmp_path / "new_vault.db"
        vault = CredentialVault(db_path=db_path)

        assert not vault.is_initialized
        vault.initialize(TEST_PASSWORD)

        assert db_path.exists()

    def test_initialize_leaves_vault_unlocked(self, tmp_vault):
        assert tmp_vault.is_unlocked

    def test_initialize_sets_is_initialized(self, tmp_vault):
        assert tmp_vault.is_initialized

    def test_double_initialize_raises(self, tmp_vault):
        with pytest.raises(VaultError, match="already initialized"):
            tmp_vault.initialize(TEST_PASSWORD)


# =============================================================================
# 2. Lock / Unlock
# =============================================================================

class TestLockUnlock:
    """Locking clears state; unlocking with correct password restores it."""

    def test_lock_clears_unlocked_state(self, tmp_vault):
        assert tmp_vault.is_unlocked
        tmp_vault.lock()
        assert not tmp_vault.is_unlocked

    def test_unlock_with_correct_password(self, locked_vault):
        assert not locked_vault.is_unlocked
        result = locked_vault.unlock(TEST_PASSWORD)
        assert result is True
        assert locked_vault.is_unlocked

    def test_unlock_with_wrong_password_raises(self, locked_vault):
        with pytest.raises(InvalidPassword):
            locked_vault.unlock("WrongPassword999!")

    def test_unlock_uninitialized_vault_raises(self, tmp_path):
        db_path = tmp_path / "empty.db"
        vault = CredentialVault(db_path=db_path)
        with pytest.raises(VaultNotInitialized):
            vault.unlock(TEST_PASSWORD)


# =============================================================================
# 3. Rate Limiting
# =============================================================================

class TestRateLimiting:
    """After MAX_UNLOCK_ATTEMPTS failed attempts, VaultLockedOut is raised."""

    def test_lockout_after_max_failed_attempts(self, locked_vault):
        for _ in range(MAX_UNLOCK_ATTEMPTS):
            with pytest.raises(InvalidPassword):
                locked_vault.unlock("BadPassword!!!")

        # Next attempt should trigger lockout, not InvalidPassword
        with pytest.raises(VaultLockedOut, match="Too many failed attempts"):
            locked_vault.unlock(TEST_PASSWORD)

    def test_lockout_duration_matches_constant(self, locked_vault):
        for _ in range(MAX_UNLOCK_ATTEMPTS):
            with pytest.raises(InvalidPassword):
                locked_vault.unlock("BadPassword!!!")

        # Vault is now locked out. Verify the lockout_until is approximately
        # UNLOCK_LOCKOUT_SECONDS in the future.
        expected_lockout_end = time.monotonic() + UNLOCK_LOCKOUT_SECONDS
        # _lockout_until was set at the moment of the 5th failure, which is
        # very close to now.  Allow a 5-second tolerance window.
        assert locked_vault._lockout_until <= expected_lockout_end + 5
        assert locked_vault._lockout_until >= expected_lockout_end - 5

    def test_lockout_resets_after_expiry(self, locked_vault):
        for _ in range(MAX_UNLOCK_ATTEMPTS):
            with pytest.raises(InvalidPassword):
                locked_vault.unlock("BadPassword!!!")

        # Simulate lockout expiry by moving the lockout_until into the past
        locked_vault._lockout_until = time.monotonic() - 1
        locked_vault._failed_attempts = MAX_UNLOCK_ATTEMPTS

        # Should succeed now with the correct password
        result = locked_vault.unlock(TEST_PASSWORD)
        assert result is True
        assert locked_vault.is_unlocked

    def test_successful_unlock_resets_failed_counter(self, locked_vault):
        # Two bad attempts
        for _ in range(2):
            with pytest.raises(InvalidPassword):
                locked_vault.unlock("BadPassword!!!")

        # Good attempt resets
        locked_vault.unlock(TEST_PASSWORD)
        assert locked_vault._failed_attempts == 0


# =============================================================================
# 4. SSH Credential CRUD
# =============================================================================

class TestSSHCredentialCRUD:
    """Add, get, list, and delete SSH credentials."""

    def test_add_and_get_ssh_credential(self, tmp_vault):
        cred_id = tmp_vault.add_ssh_credential(
            name="lab-ssh",
            username="admin",
            password="s3cret",
            port=22,
            description="Lab SSH credential",
        )
        assert isinstance(cred_id, int)
        assert cred_id > 0

        cred = tmp_vault.get_ssh_credential(name="lab-ssh")
        assert isinstance(cred, SSHCredential)
        assert cred.username == "admin"
        assert cred.password == "s3cret"
        assert cred.port == 22

    def test_get_ssh_credential_by_id(self, tmp_vault):
        cred_id = tmp_vault.add_ssh_credential(
            name="by-id",
            username="root",
            password="toor",
        )
        cred = tmp_vault.get_ssh_credential(credential_id=cred_id)
        assert cred is not None
        assert cred.username == "root"

    def test_add_ssh_credential_with_key(self, tmp_vault):
        cred_id = tmp_vault.add_ssh_credential(
            name="key-ssh",
            username="deploy",
            key_content="-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
            key_passphrase="keypass",
        )
        cred = tmp_vault.get_ssh_credential(name="key-ssh")
        assert cred.has_key
        assert cred.key_passphrase == "keypass"

    def test_add_ssh_without_password_or_key_raises(self, tmp_vault):
        with pytest.raises(ValueError, match="Must provide password or SSH key"):
            tmp_vault.add_ssh_credential(name="empty", username="admin")

    def test_list_credentials_includes_ssh(self, tmp_vault):
        tmp_vault.add_ssh_credential(name="ssh-a", username="u1", password="p1")
        tmp_vault.add_ssh_credential(name="ssh-b", username="u2", password="p2")

        infos = tmp_vault.list_credentials(credential_type=CredentialType.SSH)
        names = [i.name for i in infos]
        assert "ssh-a" in names
        assert "ssh-b" in names

    def test_delete_credential_by_name(self, tmp_vault):
        tmp_vault.add_ssh_credential(name="to-delete", username="x", password="y")
        assert tmp_vault.remove_credential(name="to-delete") is True

        cred = tmp_vault.get_ssh_credential(name="to-delete")
        assert cred is None

    def test_delete_credential_by_id(self, tmp_vault):
        cred_id = tmp_vault.add_ssh_credential(
            name="to-delete-id", username="x", password="y"
        )
        assert tmp_vault.remove_credential(credential_id=cred_id) is True

        cred = tmp_vault.get_ssh_credential(credential_id=cred_id)
        assert cred is None

    def test_delete_nonexistent_returns_false(self, tmp_vault):
        assert tmp_vault.remove_credential(name="nope") is False


# =============================================================================
# 5. SNMPv2c Credential CRUD
# =============================================================================

class TestSNMPv2cCredentialCRUD:
    """Add and get SNMPv2c credentials."""

    def test_add_and_get_snmpv2c_credential(self, tmp_vault):
        cred_id = tmp_vault.add_snmpv2c_credential(
            name="lab-snmpv2",
            community="public",
            port=161,
            timeout_seconds=3,
            retries=1,
            description="Lab read-only community",
        )
        assert isinstance(cred_id, int)

        cred = tmp_vault.get_snmpv2c_credential(name="lab-snmpv2")
        assert isinstance(cred, SNMPv2cCredential)
        assert cred.community == "public"
        assert cred.port == 161
        assert cred.timeout_seconds == 3
        assert cred.retries == 1

    def test_get_snmpv2c_by_id(self, tmp_vault):
        cred_id = tmp_vault.add_snmpv2c_credential(
            name="snmp2-byid", community="private"
        )
        cred = tmp_vault.get_snmpv2c_credential(credential_id=cred_id)
        assert cred is not None
        assert cred.community == "private"

    def test_get_nonexistent_snmpv2c_returns_none(self, tmp_vault):
        cred = tmp_vault.get_snmpv2c_credential(name="does-not-exist")
        assert cred is None

    def test_list_snmpv2c_credentials(self, tmp_vault):
        tmp_vault.add_snmpv2c_credential(name="v2-a", community="comm-a")
        tmp_vault.add_snmpv2c_credential(name="v2-b", community="comm-b")

        infos = tmp_vault.list_credentials(credential_type=CredentialType.SNMP_V2C)
        names = [i.name for i in infos]
        assert "v2-a" in names
        assert "v2-b" in names


# =============================================================================
# 6. SNMPv3 Credential CRUD
# =============================================================================

class TestSNMPv3CredentialCRUD:
    """Add and get SNMPv3 credentials."""

    def test_add_and_get_snmpv3_noauthnopriv(self, tmp_vault):
        cred_id = tmp_vault.add_snmpv3_credential(
            name="v3-noauth",
            username="snmpuser",
        )
        assert isinstance(cred_id, int)

        cred = tmp_vault.get_snmpv3_credential(name="v3-noauth")
        assert isinstance(cred, SNMPv3Credential)
        assert cred.username == "snmpuser"
        assert cred.auth_protocol == SNMPv3AuthProtocol.NONE
        assert cred.priv_protocol == SNMPv3PrivProtocol.NONE

    def test_add_and_get_snmpv3_authnopriv(self, tmp_vault):
        cred_id = tmp_vault.add_snmpv3_credential(
            name="v3-auth",
            username="authuser",
            auth_protocol=SNMPv3AuthProtocol.SHA,
            auth_password="authpass123",
        )
        cred = tmp_vault.get_snmpv3_credential(name="v3-auth")
        assert cred.auth_protocol == SNMPv3AuthProtocol.SHA
        assert cred.auth_password == "authpass123"
        assert cred.priv_protocol == SNMPv3PrivProtocol.NONE

    def test_add_and_get_snmpv3_authpriv(self, tmp_vault):
        tmp_vault.add_snmpv3_credential(
            name="v3-authpriv",
            username="privuser",
            auth_protocol=SNMPv3AuthProtocol.SHA256,
            auth_password="auth-secret",
            priv_protocol=SNMPv3PrivProtocol.AES,
            priv_password="priv-secret",
            context_name="mycontext",
            port=10161,
        )
        cred = tmp_vault.get_snmpv3_credential(name="v3-authpriv")
        assert cred.auth_protocol == SNMPv3AuthProtocol.SHA256
        assert cred.auth_password == "auth-secret"
        assert cred.priv_protocol == SNMPv3PrivProtocol.AES
        assert cred.priv_password == "priv-secret"
        assert cred.context_name == "mycontext"
        assert cred.port == 10161

    def test_snmpv3_priv_without_auth_raises(self, tmp_vault):
        with pytest.raises(ValueError, match="Privacy requires authentication"):
            tmp_vault.add_snmpv3_credential(
                name="v3-bad",
                username="u",
                priv_protocol=SNMPv3PrivProtocol.AES,
                priv_password="secret",
            )

    def test_snmpv3_auth_without_password_raises(self, tmp_vault):
        with pytest.raises(ValueError, match="Authentication protocol requires auth_password"):
            tmp_vault.add_snmpv3_credential(
                name="v3-bad2",
                username="u",
                auth_protocol=SNMPv3AuthProtocol.SHA,
            )

    def test_snmpv3_priv_without_priv_password_raises(self, tmp_vault):
        with pytest.raises(ValueError, match="Privacy protocol requires priv_password"):
            tmp_vault.add_snmpv3_credential(
                name="v3-bad3",
                username="u",
                auth_protocol=SNMPv3AuthProtocol.SHA,
                auth_password="authpass",
                priv_protocol=SNMPv3PrivProtocol.AES,
            )

    def test_get_snmpv3_by_id(self, tmp_vault):
        cred_id = tmp_vault.add_snmpv3_credential(
            name="v3-byid", username="byiduser"
        )
        cred = tmp_vault.get_snmpv3_credential(credential_id=cred_id)
        assert cred is not None
        assert cred.username == "byiduser"

    def test_get_nonexistent_snmpv3_returns_none(self, tmp_vault):
        cred = tmp_vault.get_snmpv3_credential(name="no-such-v3")
        assert cred is None


# =============================================================================
# 7. Duplicate Credential Name
# =============================================================================

class TestDuplicateCredential:
    """Adding a credential with an existing name raises DuplicateCredential."""

    def test_duplicate_ssh_name_raises(self, tmp_vault):
        tmp_vault.add_ssh_credential(name="dup-name", username="u1", password="p1")
        with pytest.raises(DuplicateCredential, match="already exists"):
            tmp_vault.add_ssh_credential(name="dup-name", username="u2", password="p2")

    def test_duplicate_snmpv2c_name_raises(self, tmp_vault):
        tmp_vault.add_snmpv2c_credential(name="dup-snmp", community="c1")
        with pytest.raises(DuplicateCredential, match="already exists"):
            tmp_vault.add_snmpv2c_credential(name="dup-snmp", community="c2")

    def test_duplicate_snmpv3_name_raises(self, tmp_vault):
        tmp_vault.add_snmpv3_credential(name="dup-v3", username="u1")
        with pytest.raises(DuplicateCredential, match="already exists"):
            tmp_vault.add_snmpv3_credential(name="dup-v3", username="u2")

    def test_duplicate_across_types_raises(self, tmp_vault):
        tmp_vault.add_ssh_credential(name="shared-name", username="u", password="p")
        with pytest.raises(DuplicateCredential, match="already exists"):
            tmp_vault.add_snmpv2c_credential(name="shared-name", community="c")


# =============================================================================
# 8. CredentialNotFound
# =============================================================================

class TestCredentialNotFound:
    """Getting a non-existent credential returns None (vault uses None, not exceptions)."""

    def test_get_ssh_nonexistent_returns_none(self, tmp_vault):
        result = tmp_vault.get_ssh_credential(name="ghost")
        assert result is None

    def test_get_snmpv2c_nonexistent_returns_none(self, tmp_vault):
        result = tmp_vault.get_snmpv2c_credential(name="ghost")
        assert result is None

    def test_get_snmpv3_nonexistent_returns_none(self, tmp_vault):
        result = tmp_vault.get_snmpv3_credential(name="ghost")
        assert result is None

    def test_get_credential_nonexistent_returns_none(self, tmp_vault):
        result = tmp_vault.get_credential(name="ghost")
        assert result is None

    def test_get_credential_info_nonexistent_returns_none(self, tmp_vault):
        result = tmp_vault.get_credential_info(name="ghost")
        assert result is None


# =============================================================================
# 9. Operations on Locked Vault
# =============================================================================

class TestLockedVaultOperations:
    """CRUD operations on a locked vault raise VaultLocked."""

    def test_add_ssh_when_locked_raises(self, locked_vault):
        with pytest.raises(VaultLocked):
            locked_vault.add_ssh_credential(
                name="x", username="u", password="p"
            )

    def test_get_ssh_when_locked_raises(self, locked_vault):
        with pytest.raises(VaultLocked):
            locked_vault.get_ssh_credential(name="x")

    def test_add_snmpv2c_when_locked_raises(self, locked_vault):
        with pytest.raises(VaultLocked):
            locked_vault.add_snmpv2c_credential(name="x", community="c")

    def test_get_snmpv2c_when_locked_raises(self, locked_vault):
        with pytest.raises(VaultLocked):
            locked_vault.get_snmpv2c_credential(name="x")

    def test_add_snmpv3_when_locked_raises(self, locked_vault):
        with pytest.raises(VaultLocked):
            locked_vault.add_snmpv3_credential(name="x", username="u")

    def test_get_snmpv3_when_locked_raises(self, locked_vault):
        with pytest.raises(VaultLocked):
            locked_vault.get_snmpv3_credential(name="x")

    def test_get_credential_when_locked_raises(self, locked_vault):
        with pytest.raises(VaultLocked):
            locked_vault.get_credential(name="x")

    def test_get_credentials_by_type_when_locked_raises(self, locked_vault):
        with pytest.raises(VaultLocked):
            locked_vault.get_credentials_by_type(CredentialType.SSH)


# =============================================================================
# 10. Change Password
# =============================================================================

class TestChangePassword:
    """Changing the master password re-encrypts credentials."""

    def test_change_password_credentials_still_accessible(self, tmp_vault):
        tmp_vault.add_ssh_credential(name="persist", username="admin", password="s3cret")
        tmp_vault.add_snmpv2c_credential(name="persist-snmp", community="public")

        new_password = "NewPassword456!"
        tmp_vault.change_password(TEST_PASSWORD, new_password)

        # Vault should still be unlocked with the new key
        assert tmp_vault.is_unlocked

        # Existing credentials must still be readable
        ssh = tmp_vault.get_ssh_credential(name="persist")
        assert ssh.username == "admin"
        assert ssh.password == "s3cret"

        snmp = tmp_vault.get_snmpv2c_credential(name="persist-snmp")
        assert snmp.community == "public"

    def test_change_password_old_password_no_longer_works(self, tmp_vault):
        new_password = "NewPassword456!"
        tmp_vault.change_password(TEST_PASSWORD, new_password)

        tmp_vault.lock()
        with pytest.raises(InvalidPassword):
            tmp_vault.unlock(TEST_PASSWORD)

    def test_change_password_new_password_unlocks(self, tmp_vault):
        new_password = "NewPassword456!"
        tmp_vault.change_password(TEST_PASSWORD, new_password)

        tmp_vault.lock()
        result = tmp_vault.unlock(new_password)
        assert result is True
        assert tmp_vault.is_unlocked


# =============================================================================
# 11. Default Credential
# =============================================================================

class TestDefaultCredential:
    """set_default and listing default credentials."""

    def test_set_default_credential(self, tmp_vault):
        cred_id = tmp_vault.add_ssh_credential(
            name="non-default", username="u", password="p"
        )
        result = tmp_vault.set_default(name="non-default")
        assert result is True

        info = tmp_vault.get_credential_info(name="non-default")
        assert info.is_default is True

    def test_set_default_clears_previous_default(self, tmp_vault):
        tmp_vault.add_ssh_credential(
            name="first", username="u1", password="p1", is_default=True
        )
        tmp_vault.add_ssh_credential(
            name="second", username="u2", password="p2"
        )

        tmp_vault.set_default(name="second")

        first_info = tmp_vault.get_credential_info(name="first")
        second_info = tmp_vault.get_credential_info(name="second")
        assert first_info.is_default is False
        assert second_info.is_default is True

    def test_set_default_nonexistent_returns_false(self, tmp_vault):
        result = tmp_vault.set_default(name="no-such-cred")
        assert result is False

    def test_add_credential_with_is_default_flag(self, tmp_vault):
        tmp_vault.add_ssh_credential(
            name="default-ssh", username="u", password="p", is_default=True
        )
        info = tmp_vault.get_credential_info(name="default-ssh")
        assert info.is_default is True

    def test_list_defaults_only(self, tmp_vault):
        tmp_vault.add_ssh_credential(
            name="ssh-def", username="u1", password="p1", is_default=True
        )
        tmp_vault.add_ssh_credential(
            name="ssh-other", username="u2", password="p2"
        )

        defaults = tmp_vault.list_credentials(include_defaults_only=True)
        names = [i.name for i in defaults]
        assert "ssh-def" in names
        assert "ssh-other" not in names

    def test_get_default_credential_name(self, tmp_vault):
        tmp_vault.add_snmpv2c_credential(
            name="snmp-def", community="c", is_default=True
        )

        defaults = tmp_vault.list_credentials(
            credential_type=CredentialType.SNMP_V2C,
            include_defaults_only=True,
        )
        assert len(defaults) == 1
        assert defaults[0].name == "snmp-def"
