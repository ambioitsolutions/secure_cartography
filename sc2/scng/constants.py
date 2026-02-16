"""
SecureCartography NG - Centralized Constants.

Single source of truth for security parameters, API configuration,
discovery defaults, and UI constants used across the codebase.
"""

# ===========================================================================
# Security Constants
# ===========================================================================

# PBKDF2 iterations - OWASP 2023 recommends 600,000 for PBKDF2-HMAC-SHA256
PBKDF2_ITERATIONS = 600_000

# Previous iteration count, kept for vault migration
PBKDF2_ITERATIONS_LEGACY = 480_000

# Minimum master password length
MIN_PASSWORD_LENGTH = 12

# Password complexity: require at least 3 of 4 character classes
PASSWORD_COMPLEXITY_REQUIRED_CLASSES = 3

# Vault unlock rate limiting
MAX_UNLOCK_ATTEMPTS = 5
UNLOCK_LOCKOUT_SECONDS = 300  # 5 minutes

# Secure file permissions (owner read/write only)
SECURE_FILE_MODE = 0o600

# ===========================================================================
# NVD API Constants
# ===========================================================================

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_REQUEST_TIMEOUT = 30
NVD_RATE_LIMIT_DELAY = 0.6  # seconds between requests (NVD rate limit)
NVD_USER_AGENT = "SecureCartography/2.0"
NVD_MAX_PARALLEL_WORKERS = 3

# ===========================================================================
# Discovery Constants
# ===========================================================================

DEFAULT_CONCURRENCY = 20
DEFAULT_TIMEOUT = 5.0
DEFAULT_MAX_DEPTH = 5
DEFAULT_SSH_PORT = 22
DEFAULT_SNMP_PORT = 161

# ===========================================================================
# UI Constants
# ===========================================================================

# Severity color definitions - single source of truth
# Each entry: (background_color, foreground_color)
SEVERITY_COLORS = {
    "CRITICAL": ("#dc2626", "#ffffff"),
    "HIGH": ("#ea580c", "#ffffff"),
    "MEDIUM": ("#ca8a04", "#ffffff"),
    "LOW": ("#16a34a", "#ffffff"),
}
