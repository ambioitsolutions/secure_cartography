"""Secure Cartography - Security Dialogs.

Dialog windows for CVE details, help, and pattern management.
"""

import csv
import webbrowser
from typing import Dict, List

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableView,
    QTextEdit,
    QVBoxLayout,
)

from .models import CVETableModel, SeverityDelegate


class CVEDetailDialog(QDialog):
    """Dialog showing full CVE details for a version"""

    def __init__(self, vendor: str, product: str, version: str,
                 cves: List[Dict], parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"CVEs for {vendor}:{product}:{version}")
        self.setMinimumSize(900, 600)
        self.cves = cves

        layout = QVBoxLayout(self)

        # Summary header
        header = QLabel(f"<b>{len(cves)} CVEs</b> affecting {vendor} {product} {version}")
        header.setStyleSheet("font-size: 14px; padding: 8px;")
        layout.addWidget(header)

        # Severity summary
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for cve in cves:
            sev = cve.get("severity", "").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        severity_text = " | ".join([
            f"<span style='color: #dc3545;'>Critical: {severity_counts['CRITICAL']}</span>",
            f"<span style='color: #fd7e14;'>High: {severity_counts['HIGH']}</span>",
            f"<span style='color: #ffc107;'>Medium: {severity_counts['MEDIUM']}</span>",
            f"<span style='color: #28a745;'>Low: {severity_counts['LOW']}</span>",
        ])
        severity_label = QLabel(severity_text)
        severity_label.setStyleSheet("padding: 4px 8px;")
        layout.addWidget(severity_label)

        # CVE table
        self.cve_model = CVETableModel()
        self.cve_model.load_cves(cves)

        self.cve_table = QTableView()
        self.cve_table.setModel(self.cve_model)
        self.cve_table.setItemDelegate(SeverityDelegate(self.cve_model, self.cve_table))
        self.cve_table.setAlternatingRowColors(False)  # Delegate handles colors
        self.cve_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.cve_table.horizontalHeader().setStretchLastSection(True)
        self.cve_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.cve_table.doubleClicked.connect(self._show_cve_detail)
        layout.addWidget(self.cve_table)

        # Detail panel for selected CVE
        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setMaximumHeight(150)
        self.detail_text.setPlaceholderText("Select a CVE to view details...")
        layout.addWidget(self.detail_text)

        self.cve_table.selectionModel().selectionChanged.connect(self._on_selection_changed)

        # Buttons
        btn_layout = QHBoxLayout()

        export_btn = QPushButton("Export CSV")
        export_btn.clicked.connect(self._export_csv)
        btn_layout.addWidget(export_btn)

        btn_layout.addStretch()

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(close_btn)

        layout.addLayout(btn_layout)

    def _on_selection_changed(self):
        """Show detail for selected CVE"""
        indexes = self.cve_table.selectedIndexes()
        if not indexes:
            return

        row = indexes[0].row()
        if row < len(self.cves):
            cve = self.cves[row]
            detail = f"<b>{cve.get('cve_id', '')}</b><br><br>"
            detail += f"<b>Severity:</b> {cve.get('severity', 'N/A')} "
            detail += f"(CVSS: {cve.get('cvss_v3_score', 'N/A')})<br>"
            detail += f"<b>Published:</b> {cve.get('published_date', 'N/A')[:10] if cve.get('published_date') else 'N/A'}<br><br>"
            detail += f"<b>Description:</b><br>{cve.get('description', 'No description available')}"
            self.detail_text.setHtml(detail)

    def _show_cve_detail(self, index):
        """Open CVE in browser on double-click"""
        row = index.row()
        if row < len(self.cves):
            cve_id = self.cves[row].get('cve_id', '')
            if cve_id:
                webbrowser.open(f"https://nvd.nist.gov/vuln/detail/{cve_id}")

    def _export_csv(self):
        """Export CVE list to CSV"""
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Export CVEs", f"cves_export.csv", "CSV Files (*.csv)"
        )
        if not filepath:
            return

        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['CVE ID', 'Severity', 'CVSS v3', 'Published', 'Description'])
                for cve in self.cves:
                    writer.writerow([
                        cve.get('cve_id', ''),
                        cve.get('severity', ''),
                        cve.get('cvss_v3_score', ''),
                        cve.get('published_date', '')[:10] if cve.get('published_date') else '',
                        cve.get('description', '')
                    ])
            QMessageBox.information(self, "Export Complete", f"Exported {len(self.cves)} CVEs to {filepath}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))


# ============================================================================
# Help Dialog
# ============================================================================

class SecurityHelpDialog(QDialog):
    """Help dialog explaining the security analysis workflow"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Security Analysis - Help")
        self.setMinimumSize(700, 500)

        layout = QVBoxLayout(self)

        # Header
        header = QLabel("🔒 Security Analysis Help")
        header.setStyleSheet("font-size: 18px; font-weight: bold; padding: 8px;")
        layout.addWidget(header)

        # Help content
        help_text = QTextEdit()
        help_text.setReadOnly(True)
        help_text.setHtml(self._get_help_content())
        layout.addWidget(help_text)

        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignRight)

    def _get_help_content(self) -> str:
        return """
        <style>
            h2 { color: #2563eb; margin-top: 16px; }
            h3 { color: #64748b; margin-top: 12px; }
            code { background: #f1f5f9; padding: 2px 6px; border-radius: 3px; }
            .note { background: #fef3c7; padding: 8px; border-radius: 4px; margin: 8px 0; }
        </style>

        <h2>Overview</h2>
        <p>The Security Analysis widget identifies known vulnerabilities (CVEs) affecting
        your discovered network devices by querying the <b>NIST National Vulnerability Database (NVD)</b>.</p>

        <h2>Workflow</h2>
        <h3>1. Export Discovery Results</h3>
        <p>From Secure Cartography's Map Viewer, use <b>Export CSV</b> to save your discovered devices.
        The CSV must include a <code>platform</code> column with OS/version strings.</p>

        <h3>2. Load CSV</h3>
        <p>Click <b>Load CSV</b> to import the discovery export. The widget will:</p>
        <ul>
            <li>Parse platform strings (e.g., "Cisco IOS 15.2(4)M11")</li>
            <li>Map to CPE format (e.g., cisco:ios:15.2(4)m11)</li>
            <li>Show confidence level for each mapping</li>
        </ul>

        <h3>3. Review Mappings</h3>
        <p>Check the <b>Discovered Platforms</b> table:</p>
        <ul>
            <li><b>High confidence</b> - Auto-mapped, ready to sync</li>
            <li><b>Low confidence</b> - May need manual correction</li>
            <li>Double-click Vendor/Product/CPE Version columns to edit</li>
        </ul>

        <h3>4. Sync with NVD</h3>
        <p>Select rows and click <b>Sync Selected</b> to query NIST NVD for vulnerabilities.</p>
        <div class="note">
            <b>Rate Limiting:</b> NVD allows 5 requests per 30 seconds without an API key.
            For faster syncing, get a free API key from <a href="https://nvd.nist.gov/developers/request-an-api-key">nvd.nist.gov</a>
        </div>

        <h3>5. Review Results</h3>
        <ul>
            <li><b>Cached Versions</b> tab - All synced versions with CVE counts</li>
            <li><b>CVEs</b> tab - Detailed CVE list for selected version</li>
            <li>Double-click a CVE to open in NVD website</li>
            <li>Double-click a cached version for detailed CVE dialog</li>
        </ul>

        <h2>Data Sources</h2>
        <table border="0" cellpadding="4">
            <tr><td><b>NVD</b></td><td>NIST National Vulnerability Database - authoritative CVE source</td></tr>
            <tr><td><b>CPE</b></td><td>Common Platform Enumeration - standardized naming for platforms</td></tr>
            <tr><td><b>CVSS</b></td><td>Common Vulnerability Scoring System - severity ratings</td></tr>
        </table>

        <h2>Cache Location</h2>
        <p>CVE data is cached locally at: <code>~/.scng/cve_cache.db</code></p>
        <p>Custom platform patterns: <code>~/.scng/platform_patterns.json</code></p>

        <h2>Tips</h2>
        <ul>
            <li>Use <b>View Cache</b> to see previously synced data without loading a new CSV</li>
            <li>Check <b>Force Re-sync</b> to refresh CVE data for already-cached versions</li>
            <li>Use <b>Add Pattern</b> to teach the parser new platform formats</li>
            <li>Export full reports via <b>Export Report</b> button</li>
        </ul>
        """


class AddPatternDialog(QDialog):
    """Dialog for adding custom platform patterns"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add Platform Pattern")
        self.setMinimumWidth(500)

        layout = QFormLayout(self)

        self.regex_input = QLineEdit()
        self.regex_input.setPlaceholderText(r"e.g., MyVendor\s+OS\s+(\d+\.\d+\.\d+)")
        layout.addRow("Regex Pattern:", self.regex_input)

        self.vendor_input = QLineEdit()
        self.vendor_input.setPlaceholderText("e.g., MyVendor")
        layout.addRow("Display Vendor:", self.vendor_input)

        self.product_input = QLineEdit()
        self.product_input.setPlaceholderText("e.g., MyOS")
        layout.addRow("Display Product:", self.product_input)

        self.cpe_vendor_input = QLineEdit()
        self.cpe_vendor_input.setPlaceholderText("e.g., myvendor (lowercase)")
        layout.addRow("CPE Vendor:", self.cpe_vendor_input)

        self.cpe_product_input = QLineEdit()
        self.cpe_product_input.setPlaceholderText("e.g., myos (lowercase)")
        layout.addRow("CPE Product:", self.cpe_product_input)

        note = QLabel("Note: The regex should have a capture group () around the version number.")
        note.setStyleSheet("color: gray; font-style: italic;")
        layout.addRow(note)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def get_pattern(self) -> dict:
        return {
            "regex": self.regex_input.text(),
            "vendor": self.vendor_input.text(),
            "product": self.product_input.text(),
            "cpe_vendor": self.cpe_vendor_input.text().lower(),
            "cpe_product": self.cpe_product_input.text().lower(),
        }
