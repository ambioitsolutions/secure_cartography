"""
Unit tests for SC2 UI widgets.

Tests cover:
- DiscoveryLogPanel: log trimming, line counting
- SVG export: JS function presence, Python method existence
- __init__.py: stale TODO removal
"""

import sys
import os
import pytest
from pathlib import Path

# Set offscreen before any Qt imports
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# Must import QtWebEngineWidgets before QApplication is created
try:
    import PyQt6.QtWebEngineWidgets  # noqa: F401
except ImportError:
    pass

from PyQt6.QtWidgets import QApplication

# Ensure QApplication exists for this module
_app = QApplication.instance()
if _app is None:
    _app = QApplication([sys.argv[0]])


# ============================================================================
# DiscoveryLogPanel: Log Trimming
# ============================================================================

class TestDiscoveryLogTrimming:
    """Tests for log trimming in DiscoveryLogPanel."""

    @pytest.fixture
    def log_panel(self):
        """Create a DiscoveryLogPanel with small max_lines for testing."""
        from sc2.ui.widgets.discovery_log import DiscoveryLogPanel
        panel = DiscoveryLogPanel(theme_manager=None, max_lines=10)
        return panel

    def test_trim_removes_old_lines(self, log_panel):
        """After exceeding max_lines, oldest lines should be removed."""
        from sc2.ui.widgets.discovery_log import LogLevel

        for i in range(15):
            log_panel.log(f"Line {i}", level=LogLevel.INFO, timestamp=False, prefix=False)

        text = log_panel.log_text.toPlainText().strip()
        lines = [l for l in text.split('\n') if l]

        assert len(lines) <= log_panel.max_lines

    def test_trim_preserves_recent_lines(self, log_panel):
        """After trimming, the most recent lines should be preserved."""
        from sc2.ui.widgets.discovery_log import LogLevel

        for i in range(15):
            log_panel.log(f"Line {i}", level=LogLevel.INFO, timestamp=False, prefix=False)

        text = log_panel.log_text.toPlainText().strip()
        lines = [l for l in text.split('\n') if l]

        assert "Line 14" in lines[-1]

    def test_no_trim_under_limit(self, log_panel):
        """Lines under max_lines should not be trimmed."""
        from sc2.ui.widgets.discovery_log import LogLevel

        for i in range(5):
            log_panel.log(f"Line {i}", level=LogLevel.INFO, timestamp=False, prefix=False)

        text = log_panel.log_text.toPlainText().strip()
        lines = [l for l in text.split('\n') if l]

        assert len(lines) == 5
        assert "Line 0" in lines[0]
        assert "Line 4" in lines[-1]

    def test_line_count_tracks_correctly(self, log_panel):
        """_line_count should track the number of logged lines."""
        from sc2.ui.widgets.discovery_log import LogLevel

        for i in range(5):
            log_panel.log(f"Line {i}", level=LogLevel.INFO, timestamp=False, prefix=False)

        assert log_panel._line_count == 5

    def test_clear_resets_line_count(self, log_panel):
        """clear() should reset _line_count to 0."""
        from sc2.ui.widgets.discovery_log import LogLevel

        for i in range(5):
            log_panel.log(f"Line {i}", level=LogLevel.INFO, timestamp=False, prefix=False)

        log_panel.clear()
        assert log_panel._line_count == 0
        assert log_panel.log_text.toPlainText() == ""

    def test_trim_updates_line_count(self, log_panel):
        """After trimming, _line_count should reflect actual block count."""
        from sc2.ui.widgets.discovery_log import LogLevel

        for i in range(15):
            log_panel.log(f"Line {i}", level=LogLevel.INFO, timestamp=False, prefix=False)

        doc = log_panel.log_text.document()
        assert log_panel._line_count == doc.blockCount()


# ============================================================================
# SVG Export: JS function and viewer method
# ============================================================================

_SRC_ROOT = Path(__file__).parent.parent.parent


class TestSVGExportFunction:
    """Tests for SVG export infrastructure."""

    def test_topology_viewer_html_has_export_svg(self):
        """The topology_viewer.html should contain exportSVG function."""
        html_path = _SRC_ROOT / "sc2" / "ui" / "widgets" / "topology_viewer.html"
        content = html_path.read_text()
        assert "exportSVG()" in content
        assert "this.cy.svg(" in content

    def test_topology_viewer_py_has_export_svg_method(self):
        """topology_viewer.py should define an export_svg method."""
        py_path = _SRC_ROOT / "sc2" / "ui" / "widgets" / "topology_viewer.py"
        content = py_path.read_text()
        assert "def export_svg(self)" in content

    def test_topology_viewer_py_has_export_png_method(self):
        """topology_viewer.py should still define export_png_base64 method."""
        py_path = _SRC_ROOT / "sc2" / "ui" / "widgets" / "topology_viewer.py"
        content = py_path.read_text()
        assert "def export_png_base64(self)" in content

    def test_map_viewer_has_svg_in_export_combo(self):
        """MapViewerDialog source should include SVG export option."""
        dialog_path = _SRC_ROOT / "sc2" / "ui" / "widgets" / "map_viewer_dialog.py"
        content = dialog_path.read_text()
        assert '"SVG"' in content
        assert '"svg"' in content
        assert "_on_export_svg" in content

    def test_map_viewer_has_svg_export_handler(self):
        """MapViewerDialog should have _on_export_svg method."""
        dialog_path = _SRC_ROOT / "sc2" / "ui" / "widgets" / "map_viewer_dialog.py"
        content = dialog_path.read_text()
        assert "def _on_export_svg(self):" in content
        assert 'SVG Images (*.svg)' in content

    def test_export_svg_js_uses_cy_svg(self):
        """The JS exportSVG function should call this.cy.svg()."""
        html_path = _SRC_ROOT / "sc2" / "ui" / "widgets" / "topology_viewer.html"
        content = html_path.read_text()
        # Find exportSVG block and verify it calls cy.svg
        assert "exportSVG()" in content
        idx = content.index("exportSVG()")
        block = content[idx:idx + 200]
        assert "this.cy.svg(" in block


# ============================================================================
# __init__.py: MainWindow import (stale TODO removed)
# ============================================================================

class TestUIInit:
    """Tests for sc2.ui __init__ module."""

    def test_no_stale_todo_in_init(self):
        """The __init__.py should not contain the stale TODO placeholder."""
        init_path = _SRC_ROOT / "sc2" / "ui" / "__init__.py"
        content = init_path.read_text()
        assert "TODO: Implement MainWindow" not in content
        assert "Main window coming soon" not in content

    def test_init_imports_main_window_in_main(self):
        """The main() function should import MainWindow, not use a placeholder."""
        init_path = _SRC_ROOT / "sc2" / "ui" / "__init__.py"
        content = init_path.read_text()
        assert "from .main_window import MainWindow" in content
