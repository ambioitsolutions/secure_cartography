"""
SecureCartography NG - Credential Access Audit Log.

Logs all credential operations (access, add, remove, test) for
security auditing and compliance.

Logs to both Python logging and a dedicated audit file.
"""

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("sc2.audit.credentials")

# Default audit log location
_AUDIT_DIR = Path.home() / ".scng" / "audit"
_audit_handler: Optional[logging.FileHandler] = None


def _ensure_audit_handler() -> None:
    """Lazily set up file handler for audit log."""
    global _audit_handler
    if _audit_handler is not None:
        return

    _AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    audit_file = _AUDIT_DIR / "credential_access.log"

    _audit_handler = logging.FileHandler(audit_file, encoding="utf-8")
    _audit_handler.setFormatter(
        logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S%z")
    )
    logger.addHandler(_audit_handler)
    logger.setLevel(logging.INFO)

    # Secure the log file
    try:
        os.chmod(audit_file, 0o600)
    except OSError:
        pass


def log_credential_access(
    operation: str,
    credential_name: Optional[str] = None,
    credential_type: Optional[str] = None,
    target_host: Optional[str] = None,
    success: bool = True,
    detail: str = "",
) -> None:
    """
    Log a credential operation for audit purposes.

    Args:
        operation: One of 'access', 'add', 'remove', 'test', 'unlock', 'lock',
                   'change_password', 'list'.
        credential_name: Name of the credential (if applicable).
        credential_type: Type (ssh, snmp_v2c, snmp_v3).
        target_host: Target host for test operations.
        success: Whether the operation succeeded.
        detail: Additional detail string.
    """
    _ensure_audit_handler()

    user = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
    status = "OK" if success else "FAIL"

    parts = [f"op={operation}", f"user={user}", f"status={status}"]
    if credential_name:
        parts.append(f"cred={credential_name}")
    if credential_type:
        parts.append(f"type={credential_type}")
    if target_host:
        parts.append(f"target={target_host}")
    if detail:
        parts.append(f"detail={detail}")

    message = " ".join(parts)
    logger.info(message)
