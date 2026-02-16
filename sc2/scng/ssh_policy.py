"""
SecureCartography NG - SSH Host Key Policy.

Replaces paramiko.AutoAddPolicy with a logging policy that accepts
keys but emits warnings with fingerprint details.
"""

import hashlib
import logging

import paramiko

logger = logging.getLogger(__name__)


class LoggingPolicy(paramiko.MissingHostKeyPolicy):
    """
    Accept unknown host keys but log a warning with the key fingerprint.

    This is safer than AutoAddPolicy because it creates an audit trail
    for host key changes that could indicate MITM attacks.
    """

    def missing_host_key(self, client, hostname, key):
        fingerprint = hashlib.sha256(key.asbytes()).hexdigest()
        key_type = key.get_name()
        logger.warning(
            "Accepting unknown %s host key for %s: SHA256:%s",
            key_type,
            hostname,
            fingerprint,
        )


def get_ssh_policy() -> paramiko.MissingHostKeyPolicy:
    """
    Factory function returning the project-standard SSH host key policy.

    Returns:
        LoggingPolicy instance that logs unknown host key fingerprints.
    """
    return LoggingPolicy()
