"""
Tests for sc2.scng.creds.encryption module.

Covers password validation, VaultEncryption lifecycle (initialize, unlock, lock,
encrypt/decrypt, change_password), and standalone utility functions.
"""

import re

import pytest

from sc2.scng.creds.encryption import (
    DecryptionFailed,
    EncryptionError,
    InvalidPassword,
    VaultEncryption,
    VaultLocked,
    generate_random_password,
    hash_for_display,
    validate_password_strength,
)
from sc2.scng.constants import (
    MIN_PASSWORD_LENGTH,
    PASSWORD_COMPLEXITY_REQUIRED_CLASSES,
)

# Master password used throughout the test suite.
# Meets the 12-char minimum and 3-of-4 character-class requirement
# (uppercase, lowercase, digit, special).
TEST_PASSWORD = "TestPassword123!"


# ---------------------------------------------------------------------------
# Helper: create an initialized (unlocked) VaultEncryption and return it
# together with the salt and password hash produced during initialization.
# ---------------------------------------------------------------------------

def _initialized_vault(password: str = TEST_PASSWORD):
    """Return (vault, salt, pw_hash) after initialization."""
    vault = VaultEncryption()
    salt, pw_hash = vault.initialize(password)
    return vault, salt, pw_hash


# ===========================================================================
# 1. validate_password_strength
# ===========================================================================

class TestValidatePasswordStrength:
    """Tests for the standalone validate_password_strength function."""

    def test_too_short_raises_value_error(self):
        """A password shorter than MIN_PASSWORD_LENGTH must be rejected."""
        short = "Ab1!" * 2  # 8 chars -- below the 12-char minimum
        assert len(short) < MIN_PASSWORD_LENGTH
        with pytest.raises(ValueError, match="at least"):
            validate_password_strength(short)

    def test_exactly_min_length_but_insufficient_classes(self):
        """A password of sufficient length but only 1 character class fails."""
        # 12 lowercase letters -- only 1 class
        only_lower = "a" * MIN_PASSWORD_LENGTH
        with pytest.raises(ValueError, match="uppercase|lowercase|digits|special"):
            validate_password_strength(only_lower)

    def test_two_classes_insufficient(self):
        """Two character classes should still fail (need 3)."""
        two_classes = "abcdefABCDEF"  # lower + upper = 2 classes, 12 chars
        assert len(two_classes) >= MIN_PASSWORD_LENGTH
        with pytest.raises(ValueError):
            validate_password_strength(two_classes)

    def test_three_classes_valid(self):
        """Three character classes with sufficient length must pass."""
        three_classes = "abcdefABCD12"  # lower + upper + digit = 3 classes
        assert len(three_classes) >= MIN_PASSWORD_LENGTH
        # Should not raise
        validate_password_strength(three_classes)

    def test_four_classes_valid(self):
        """All four character classes with sufficient length must pass."""
        validate_password_strength(TEST_PASSWORD)

    def test_valid_password_returns_none(self):
        """validate_password_strength returns None on success."""
        result = validate_password_strength(TEST_PASSWORD)
        assert result is None


# ===========================================================================
# 2. VaultEncryption.initialize
# ===========================================================================

class TestVaultInitialize:
    """Tests for VaultEncryption.initialize."""

    def test_returns_salt_and_hash(self):
        """initialize() returns a (salt, password_hash) tuple of bytes."""
        vault = VaultEncryption()
        result = vault.initialize(TEST_PASSWORD)
        salt, pw_hash = result
        assert isinstance(salt, bytes)
        assert isinstance(pw_hash, bytes)
        assert len(salt) == 16  # SALT_SIZE
        assert len(pw_hash) > 0

    def test_vault_unlocked_after_initialize(self):
        """The vault should be unlocked immediately after initialization."""
        vault, _, _ = _initialized_vault()
        assert vault.is_unlocked is True

    def test_different_salts_each_call(self):
        """Each initialization must produce a unique random salt."""
        vault1 = VaultEncryption()
        salt1, _ = vault1.initialize(TEST_PASSWORD)
        vault2 = VaultEncryption()
        salt2, _ = vault2.initialize(TEST_PASSWORD)
        assert salt1 != salt2

    def test_weak_password_rejected(self):
        """initialize() validates password strength before proceeding."""
        vault = VaultEncryption()
        with pytest.raises(ValueError):
            vault.initialize("short")


# ===========================================================================
# 3. VaultEncryption.unlock
# ===========================================================================

class TestVaultUnlock:
    """Tests for VaultEncryption.unlock."""

    def test_correct_password_unlocks(self):
        """Unlocking with the correct password returns True and unlocks."""
        _, salt, pw_hash = _initialized_vault()
        vault = VaultEncryption()
        result = vault.unlock(TEST_PASSWORD, salt, pw_hash)
        assert result is True
        assert vault.is_unlocked is True

    def test_wrong_password_raises_invalid_password(self):
        """Unlocking with the wrong password raises InvalidPassword."""
        _, salt, pw_hash = _initialized_vault()
        vault = VaultEncryption()
        with pytest.raises(InvalidPassword):
            vault.unlock("WrongPassword999!", salt, pw_hash)

    def test_invalid_password_is_encryption_error(self):
        """InvalidPassword should be a subclass of EncryptionError."""
        assert issubclass(InvalidPassword, EncryptionError)


# ===========================================================================
# 4. VaultEncryption.encrypt / decrypt  (string roundtrip)
# ===========================================================================

class TestEncryptDecrypt:
    """Tests for string-level encrypt and decrypt."""

    def test_roundtrip(self):
        """Encrypting then decrypting recovers the original plaintext."""
        vault, _, _ = _initialized_vault()
        plaintext = "super-secret credential"
        ciphertext = vault.encrypt(plaintext)
        assert isinstance(ciphertext, str)
        assert ciphertext != plaintext
        assert vault.decrypt(ciphertext) == plaintext

    def test_encrypt_locked_raises_vault_locked(self):
        """encrypt() on a locked vault raises VaultLocked."""
        vault = VaultEncryption()
        with pytest.raises(VaultLocked):
            vault.encrypt("data")

    def test_decrypt_locked_raises_vault_locked(self):
        """decrypt() on a locked vault raises VaultLocked."""
        vault = VaultEncryption()
        with pytest.raises(VaultLocked):
            vault.decrypt("data")

    def test_vault_locked_is_encryption_error(self):
        """VaultLocked should be a subclass of EncryptionError."""
        assert issubclass(VaultLocked, EncryptionError)

    def test_empty_string_roundtrip(self):
        """An empty string should survive the encrypt/decrypt roundtrip."""
        vault, _, _ = _initialized_vault()
        assert vault.decrypt(vault.encrypt("")) == ""

    def test_unicode_roundtrip(self):
        """Non-ASCII / unicode plaintext should survive the roundtrip."""
        vault, _, _ = _initialized_vault()
        text = "Voil\u00e0! Caf\u00e9 \u2014 \u00e9l\u00e8ve \u2603 \u2764"
        assert vault.decrypt(vault.encrypt(text)) == text


# ===========================================================================
# 5. VaultEncryption.encrypt_bytes / decrypt_bytes
# ===========================================================================

class TestEncryptDecryptBytes:
    """Tests for raw-bytes encrypt and decrypt."""

    def test_roundtrip(self):
        """encrypt_bytes / decrypt_bytes round-trips arbitrary bytes."""
        vault, _, _ = _initialized_vault()
        data = b"\x00\x01\x02\xff" * 64
        ciphertext = vault.encrypt_bytes(data)
        assert isinstance(ciphertext, bytes)
        assert ciphertext != data
        assert vault.decrypt_bytes(ciphertext) == data

    def test_encrypt_bytes_locked_raises_vault_locked(self):
        """encrypt_bytes() on a locked vault raises VaultLocked."""
        vault = VaultEncryption()
        with pytest.raises(VaultLocked):
            vault.encrypt_bytes(b"data")

    def test_decrypt_bytes_locked_raises_vault_locked(self):
        """decrypt_bytes() on a locked vault raises VaultLocked."""
        vault = VaultEncryption()
        with pytest.raises(VaultLocked):
            vault.decrypt_bytes(b"data")

    def test_empty_bytes_roundtrip(self):
        """Empty bytes should survive the roundtrip."""
        vault, _, _ = _initialized_vault()
        assert vault.decrypt_bytes(vault.encrypt_bytes(b"")) == b""


# ===========================================================================
# 6. VaultEncryption.lock
# ===========================================================================

class TestVaultLock:
    """Tests for VaultEncryption.lock."""

    def test_lock_clears_key_material(self):
        """After lock(), the internal key material reference is None."""
        vault, _, _ = _initialized_vault()
        assert vault.is_unlocked is True
        vault.lock()
        assert vault._key_material is None

    def test_is_unlocked_false_after_lock(self):
        """is_unlocked must be False after locking."""
        vault, _, _ = _initialized_vault()
        vault.lock()
        assert vault.is_unlocked is False

    def test_encrypt_after_lock_raises(self):
        """Crypto operations must fail after the vault is locked."""
        vault, _, _ = _initialized_vault()
        vault.lock()
        with pytest.raises(VaultLocked):
            vault.encrypt("data")

    def test_lock_idempotent(self):
        """Calling lock() on an already-locked vault should not raise."""
        vault = VaultEncryption()
        vault.lock()  # never initialized -- should be fine
        vault.lock()  # second call -- still fine


# ===========================================================================
# 7. VaultEncryption.change_password
# ===========================================================================

class TestChangePassword:
    """Tests for VaultEncryption.change_password."""

    NEW_PASSWORD = "NewSecure456!@#"

    def test_change_password_returns_new_salt_and_hash(self):
        """change_password returns (new_salt, new_pw_hash) tuple."""
        _, salt, pw_hash = _initialized_vault()
        vault = VaultEncryption()
        new_salt, new_pw_hash = vault.change_password(
            TEST_PASSWORD, self.NEW_PASSWORD, salt, pw_hash
        )
        assert isinstance(new_salt, bytes)
        assert isinstance(new_pw_hash, bytes)
        # New material should differ from the old
        assert new_salt != salt
        assert new_pw_hash != pw_hash

    def test_vault_unlocked_with_new_password(self):
        """After change, vault is unlocked and usable with the new key."""
        _, salt, pw_hash = _initialized_vault()
        vault = VaultEncryption()
        vault.change_password(TEST_PASSWORD, self.NEW_PASSWORD, salt, pw_hash)
        assert vault.is_unlocked is True
        # Encrypt/decrypt still works
        ct = vault.encrypt("after change")
        assert vault.decrypt(ct) == "after change"

    def test_re_encrypt_with_new_key(self):
        """Data encrypted before change can be re-encrypted under new key."""
        vault, salt, pw_hash = _initialized_vault()
        original = "re-encrypt me"
        old_ciphertext = vault.encrypt(original)

        # Change password -- vault is now keyed to NEW_PASSWORD
        new_salt, new_pw_hash = vault.change_password(
            TEST_PASSWORD, self.NEW_PASSWORD, salt, pw_hash
        )

        # Old ciphertext cannot be decrypted with new key
        with pytest.raises(DecryptionFailed):
            vault.decrypt(old_ciphertext)

        # Re-encrypt under new key
        new_ciphertext = vault.encrypt(original)
        assert vault.decrypt(new_ciphertext) == original

    def test_wrong_current_password_raises(self):
        """change_password rejects an incorrect current password."""
        _, salt, pw_hash = _initialized_vault()
        vault = VaultEncryption()
        with pytest.raises(InvalidPassword):
            vault.change_password(
                "WrongPassword999!", self.NEW_PASSWORD, salt, pw_hash
            )

    def test_weak_new_password_raises(self):
        """change_password validates the new password strength."""
        _, salt, pw_hash = _initialized_vault()
        vault = VaultEncryption()
        with pytest.raises(ValueError):
            vault.change_password(TEST_PASSWORD, "weak", salt, pw_hash)

    def test_unlock_with_new_password_after_change(self):
        """After change, a fresh vault can unlock with the new credentials."""
        _, salt, pw_hash = _initialized_vault()
        vault = VaultEncryption()
        new_salt, new_pw_hash = vault.change_password(
            TEST_PASSWORD, self.NEW_PASSWORD, salt, pw_hash
        )
        # Fresh vault unlocks with new credentials
        fresh = VaultEncryption()
        assert fresh.unlock(self.NEW_PASSWORD, new_salt, new_pw_hash) is True


# ===========================================================================
# 8. DecryptionFailed
# ===========================================================================

class TestDecryptionFailed:
    """Tests that DecryptionFailed is raised for wrong-key decryption."""

    def test_wrong_key_decrypt_raises_decryption_failed(self):
        """Decrypting ciphertext with a different key raises DecryptionFailed."""
        vault_a, _, _ = _initialized_vault()
        ciphertext = vault_a.encrypt("secret")

        # Initialize a second vault with a different key (same password, new salt)
        vault_b, _, _ = _initialized_vault()
        with pytest.raises(DecryptionFailed):
            vault_b.decrypt(ciphertext)

    def test_corrupted_ciphertext_raises_decryption_failed(self):
        """Corrupted ciphertext must raise DecryptionFailed."""
        vault, _, _ = _initialized_vault()
        ciphertext = vault.encrypt("test")
        # Flip a character in the middle of the ciphertext
        corrupted = ciphertext[:10] + "Z" + ciphertext[11:]
        with pytest.raises(DecryptionFailed):
            vault.decrypt(corrupted)

    def test_wrong_key_decrypt_bytes_raises_decryption_failed(self):
        """decrypt_bytes with a different key raises DecryptionFailed."""
        vault_a, _, _ = _initialized_vault()
        ct = vault_a.encrypt_bytes(b"bytes secret")

        vault_b, _, _ = _initialized_vault()
        with pytest.raises(DecryptionFailed):
            vault_b.decrypt_bytes(ct)

    def test_decryption_failed_is_encryption_error(self):
        """DecryptionFailed should be a subclass of EncryptionError."""
        assert issubclass(DecryptionFailed, EncryptionError)


# ===========================================================================
# 9. generate_random_password
# ===========================================================================

class TestGenerateRandomPassword:
    """Tests for the generate_random_password utility."""

    def test_default_length(self):
        """Default generated password is 32 characters."""
        pw = generate_random_password()
        assert len(pw) == 32

    def test_custom_length(self):
        """Requesting a specific length is honoured."""
        pw = generate_random_password(length=64)
        assert len(pw) == 64

    def test_contains_multiple_char_classes(self):
        """Generated password (at default length) should contain at least 3
        character classes with overwhelming probability."""
        # Run a few times to reduce flakiness risk (P(fail) ~ 0 at length 32)
        for _ in range(5):
            pw = generate_random_password()
            classes = 0
            if re.search(r'[a-z]', pw):
                classes += 1
            if re.search(r'[A-Z]', pw):
                classes += 1
            if re.search(r'[0-9]', pw):
                classes += 1
            if re.search(r'[^a-zA-Z0-9]', pw):
                classes += 1
            assert classes >= PASSWORD_COMPLEXITY_REQUIRED_CLASSES

    def test_only_expected_characters(self):
        """Generated password uses only the declared alphabet."""
        allowed = set(
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "!@#$%^&*"
        )
        pw = generate_random_password(length=200)
        assert set(pw).issubset(allowed)

    def test_uniqueness(self):
        """Two calls should produce distinct passwords."""
        pw1 = generate_random_password()
        pw2 = generate_random_password()
        assert pw1 != pw2


# ===========================================================================
# 10. hash_for_display
# ===========================================================================

class TestHashForDisplay:
    """Tests for the hash_for_display utility."""

    def test_default_length(self):
        """Default output is 8 hex characters."""
        result = hash_for_display("hello")
        assert len(result) == 8

    def test_custom_length(self):
        """Custom length parameter is respected."""
        result = hash_for_display("hello", length=16)
        assert len(result) == 16

    def test_hex_string(self):
        """Output must be a valid lowercase hex string."""
        result = hash_for_display("test data")
        assert re.fullmatch(r'[0-9a-f]+', result)

    def test_deterministic(self):
        """Same input must always produce the same hash."""
        a = hash_for_display("deterministic")
        b = hash_for_display("deterministic")
        assert a == b

    def test_different_inputs_differ(self):
        """Different inputs should produce different hashes."""
        a = hash_for_display("alpha")
        b = hash_for_display("bravo")
        assert a != b
