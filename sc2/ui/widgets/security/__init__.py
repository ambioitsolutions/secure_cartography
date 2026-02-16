"""
SecureCartography - Security Analysis Package.

Split from the monolithic security_widget.py for independent testability.
Backward-compatible re-exports ensure existing imports continue to work.
"""

from .platform_parser import ParsedPlatform, PlatformParser
from .cve_cache import CVECache
from .models import PlatformTableModel, CVETableModel, CachedVersionsModel, SeverityDelegate
from .workers import SyncWorker
from .dialogs import CVEDetailDialog, SecurityHelpDialog, AddPatternDialog

# SecurityWidget import deferred to avoid circular imports - it's in the
# parent module (security_widget.py) which imports from this package.

__all__ = [
    "ParsedPlatform",
    "PlatformParser",
    "CVECache",
    "PlatformTableModel",
    "CVETableModel",
    "CachedVersionsModel",
    "SeverityDelegate",
    "SyncWorker",
    "CVEDetailDialog",
    "SecurityHelpDialog",
    "AddPatternDialog",
]
