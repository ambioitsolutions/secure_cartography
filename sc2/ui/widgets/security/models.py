"""Secure Cartography - Security Qt Models.

Qt table models and delegates for CVE data display.
"""

from typing import Dict, List, Optional

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtWidgets import QStyle, QStyledItemDelegate

from sc2.scng.constants import SEVERITY_COLORS
from .platform_parser import ParsedPlatform


class PlatformTableModel(QAbstractTableModel):
    """Model for the platform/CPE mapping table"""

    COLUMNS = ["Platform", "Vendor", "Product", "Version", "CPE Version",
               "Devices", "Confidence", "Status"]

    def __init__(self):
        super().__init__()
        self.platforms: List[ParsedPlatform] = []
        self.sync_status: Dict[str, str] = {}  # raw -> status

    def load_platforms(self, platforms: List[ParsedPlatform]):
        self.beginResetModel()
        self.platforms = platforms
        self.sync_status = {p.raw: "pending" for p in platforms}
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self.platforms)

    def columnCount(self, parent=QModelIndex()):
        return len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self.platforms):
            return None

        p = self.platforms[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0: return p.raw[:60] + "..." if len(p.raw) > 60 else p.raw
            if col == 1: return p.cpe_vendor
            if col == 2: return p.cpe_product
            if col == 3: return p.version
            if col == 4: return p.cpe_version
            if col == 5: return str(p.device_count)
            if col == 6: return p.confidence
            if col == 7: return self.sync_status.get(p.raw, "pending")

        elif role == Qt.ItemDataRole.BackgroundRole:
            status = self.sync_status.get(p.raw, "pending")
            if status == "synced":
                return QBrush(QColor("#d4edda"))
            elif status == "error":
                return QBrush(QColor("#f8d7da"))
            elif status == "syncing":
                return QBrush(QColor("#fff3cd"))
            elif p.confidence == "low":
                return QBrush(QColor("#fff3cd"))

        elif role == Qt.ItemDataRole.ToolTipRole:
            if col == 0:
                return p.raw
            elif col == 4:
                return p.to_cpe()

        return None

    def setData(self, index, value, role=Qt.ItemDataRole.EditRole):
        if not index.isValid() or role != Qt.ItemDataRole.EditRole:
            return False

        p = self.platforms[index.row()]
        col = index.column()

        # Allow editing CPE fields
        if col == 1:
            p.cpe_vendor = value.lower().strip()
        elif col == 2:
            p.cpe_product = value.lower().strip()
        elif col == 4:
            p.cpe_version = value.lower().strip()
        else:
            return False

        p.confidence = "manual"
        self.dataChanged.emit(index, index)
        return True

    def flags(self, index):
        flags = super().flags(index)
        # Make CPE columns editable
        if index.column() in [1, 2, 4]:
            flags |= Qt.ItemFlag.ItemIsEditable
        return flags

    def update_status(self, raw: str, status: str):
        """Update sync status for a platform"""
        self.sync_status[raw] = status
        for i, p in enumerate(self.platforms):
            if p.raw == raw:
                idx = self.index(i, 7)
                self.dataChanged.emit(idx, idx)
                break

    def get_selected_for_sync(self, rows: List[int]) -> List[ParsedPlatform]:
        """Get platforms ready for sync (have valid CPE data)"""
        result = []
        for row in rows:
            if row < len(self.platforms):
                p = self.platforms[row]
                if p.cpe_vendor and p.cpe_product and p.cpe_version:
                    result.append(p)
        return result


class SeverityDelegate(QStyledItemDelegate):
    """Custom delegate to paint severity colors that override stylesheets"""

    def __init__(self, model, parent=None):
        super().__init__(parent)
        self.model = model

    def paint(self, painter, option, index):
        # Get severity from model
        if index.row() < len(self.model.cves):
            severity = self.model.cves[index.row()].get("severity", "").upper()

            if severity in SEVERITY_COLORS:
                bg_color, fg_color = SEVERITY_COLORS[severity]

                # Fill background
                painter.fillRect(option.rect, QColor(bg_color))

                # Handle selection highlight
                if option.state & QStyle.StateFlag.State_Selected:
                    painter.fillRect(option.rect, QColor(255, 255, 255, 60))

                # Draw text
                painter.setPen(QColor(fg_color))
                text = index.data(Qt.ItemDataRole.DisplayRole)
                if text:
                    text_rect = option.rect.adjusted(6, 0, -6, 0)
                    painter.drawText(text_rect, Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, str(text))
                return

        # Fall back to default painting
        super().paint(painter, option, index)


class CVETableModel(QAbstractTableModel):
    """Model for displaying CVE results"""

    COLUMNS = ["CVE ID", "Severity", "CVSS", "Published", "Description"]

    def __init__(self):
        super().__init__()
        self.cves: List[Dict] = []

    def load_cves(self, cves: List[Dict]):
        self.beginResetModel()
        self.cves = cves
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self.cves)

    def columnCount(self, parent=QModelIndex()):
        return len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self.cves):
            return None

        cve = self.cves[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0: return cve.get("cve_id", "")
            if col == 1: return cve.get("severity", "")
            if col == 2: return str(cve.get("cvss_v3_score", "")) if cve.get("cvss_v3_score") else ""
            if col == 3: return cve.get("published_date", "")[:10] if cve.get("published_date") else ""
            if col == 4:
                desc = cve.get("description", "")
                return desc[:100] + "..." if len(desc) > 100 else desc

        elif role == Qt.ItemDataRole.BackgroundRole:
            severity = cve.get("severity", "").upper()
            if severity in SEVERITY_COLORS:
                bg_color, _fg_color = SEVERITY_COLORS[severity]
                return QBrush(QColor(bg_color))

        elif role == Qt.ItemDataRole.ToolTipRole:
            if col == 4:
                return cve.get("description", "")

        return None


class CachedVersionsModel(QAbstractTableModel):
    """Model for displaying cached/synced versions from the database"""

    COLUMNS = ["Vendor", "Product", "Version", "CVEs", "Critical", "High", "Medium", "Low", "Last Synced"]

    def __init__(self):
        super().__init__()
        self.versions: List[Dict] = []

    def load_versions(self, versions: List[Dict]):
        self.beginResetModel()
        self.versions = versions
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return len(self.versions)

    def columnCount(self, parent=QModelIndex()):
        return len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.COLUMNS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self.versions):
            return None

        v = self.versions[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0: return v.get("vendor", "")
            if col == 1: return v.get("product", "")
            if col == 2: return v.get("version", "")
            if col == 3: return str(v.get("cve_count", 0))
            if col == 4: return str(v.get("critical_count", 0))
            if col == 5: return str(v.get("high_count", 0))
            if col == 6: return str(v.get("medium_count", 0))
            if col == 7: return str(v.get("low_count", 0))
            if col == 8:
                synced = v.get("last_synced", "")
                return synced[:10] if synced else ""

        elif role == Qt.ItemDataRole.BackgroundRole:
            # Highlight rows with critical CVEs
            critical = v.get("critical_count", 0)
            high = v.get("high_count", 0)
            if critical > 0:
                return QBrush(QColor("#f8d7da"))
            elif high > 5:
                return QBrush(QColor("#ffe5d0"))

        elif role == Qt.ItemDataRole.TextAlignmentRole:
            if col >= 3:  # Numeric columns
                return Qt.AlignmentFlag.AlignCenter

        return None

    def get_version_at(self, row: int) -> Optional[Dict]:
        """Get version data at row"""
        if 0 <= row < len(self.versions):
            return self.versions[row]
        return None
