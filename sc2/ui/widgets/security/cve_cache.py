"""
Secure Cartography - CVE Cache.

SQLite-backed cache for NVD CVE vulnerability data.
"""

import logging
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

import requests

from sc2.scng.constants import NVD_BASE_URL, NVD_REQUEST_TIMEOUT, NVD_USER_AGENT

logger = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_records (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    severity TEXT,
    cvss_v3_score REAL,
    cvss_v3_vector TEXT,
    cvss_v2_score REAL,
    cvss_v2_vector TEXT,
    published_date TEXT,
    last_modified TEXT,
    cached_at TEXT
);

CREATE TABLE IF NOT EXISTS cpe_cve_mapping (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT REFERENCES cve_records(cve_id),
    cpe_vendor TEXT,
    cpe_product TEXT,
    version_exact TEXT,
    UNIQUE(cve_id, cpe_vendor, cpe_product, version_exact)
);

CREATE TABLE IF NOT EXISTS synced_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor TEXT,
    product TEXT,
    version TEXT,
    cve_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    last_synced TEXT,
    UNIQUE(vendor, product, version)
);

CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_records(severity);
CREATE INDEX IF NOT EXISTS idx_cpe_mapping ON cpe_cve_mapping(cpe_vendor, cpe_product, version_exact);
"""


class CVECache:
    """SQLite cache for NVD CVE data"""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    def reconnect(self):
        """Reconnect to database - use after external writes"""
        self.conn.close()
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

    def is_version_synced(self, vendor: str, product: str, version: str) -> bool:
        """Check if a version has been synced"""
        row = self.conn.execute(
            "SELECT 1 FROM synced_versions WHERE vendor=? AND product=? AND version=?",
            (vendor.lower(), product.lower(), version.lower())
        ).fetchone()
        return row is not None

    def sync_version(self, vendor: str, product: str, version: str,
                     api_key: Optional[str] = None) -> Dict:
        """
        Sync CVEs for a single version from NVD

        Returns dict with sync results
        """
        cpe = f"cpe:2.3:o:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        encoded_cpe = quote(cpe, safe='')
        url = f"{NVD_BASE_URL}?cpeName={encoded_cpe}"

        headers = {'User-Agent': NVD_USER_AGENT}
        if api_key:
            headers['apiKey'] = api_key

        try:
            response = requests.get(url, headers=headers, timeout=NVD_REQUEST_TIMEOUT)

            if response.status_code != 200:
                return {"error": f"HTTP {response.status_code}", "cve_count": 0}

            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

            for vuln in vulnerabilities:
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "")

                # Extract CVSS data
                metrics = cve_data.get("metrics", {})
                severity, cvss_v3_score, cvss_v3_vector = self._extract_cvss_v3(metrics)
                cvss_v2_score, cvss_v2_vector = self._extract_cvss_v2(metrics)

                if severity in severity_counts:
                    severity_counts[severity] += 1

                # Get description
                description = ""
                for desc in cve_data.get("descriptions", []):
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                # Upsert CVE record
                self.conn.execute("""
                    INSERT INTO cve_records (cve_id, description, severity,
                        cvss_v3_score, cvss_v3_vector, cvss_v2_score, cvss_v2_vector,
                        published_date, last_modified, cached_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        description=excluded.description,
                        severity=excluded.severity,
                        cvss_v3_score=excluded.cvss_v3_score,
                        cached_at=excluded.cached_at
                """, (
                    cve_id, description, severity,
                    cvss_v3_score, cvss_v3_vector, cvss_v2_score, cvss_v2_vector,
                    cve_data.get("published"), cve_data.get("lastModified"),
                    datetime.now(timezone.utc).isoformat()
                ))

                # Add CPE mapping
                self.conn.execute("""
                    INSERT OR IGNORE INTO cpe_cve_mapping
                    (cve_id, cpe_vendor, cpe_product, version_exact)
                    VALUES (?, ?, ?, ?)
                """, (cve_id, vendor.lower(), product.lower(), version.lower()))

            # Update synced_versions
            self.conn.execute("""
                INSERT INTO synced_versions (vendor, product, version, cve_count,
                    critical_count, high_count, medium_count, low_count, last_synced)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(vendor, product, version) DO UPDATE SET
                    cve_count=excluded.cve_count,
                    critical_count=excluded.critical_count,
                    high_count=excluded.high_count,
                    medium_count=excluded.medium_count,
                    low_count=excluded.low_count,
                    last_synced=excluded.last_synced
            """, (
                vendor.lower(), product.lower(), version.lower(),
                len(vulnerabilities),
                severity_counts["CRITICAL"], severity_counts["HIGH"],
                severity_counts["MEDIUM"], severity_counts["LOW"],
                datetime.now(timezone.utc).isoformat()
            ))

            self.conn.commit()

            return {
                "cve_count": len(vulnerabilities),
                "critical": severity_counts["CRITICAL"],
                "high": severity_counts["HIGH"],
                "medium": severity_counts["MEDIUM"],
                "low": severity_counts["LOW"],
            }

        except Exception as e:
            logger.error(f"Sync failed for {vendor}:{product}:{version}: {e}")
            return {"error": str(e), "cve_count": 0}

    def _extract_cvss_v3(self, metrics: Dict) -> Tuple[str, Optional[float], Optional[str]]:
        """Extract CVSS v3.x severity, score, vector"""
        for key in ["cvssMetricV31", "cvssMetricV30"]:
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss = m.get("cvssData", {})
                return (
                    cvss.get("baseSeverity", "UNKNOWN"),
                    cvss.get("baseScore"),
                    cvss.get("vectorString")
                )
        return ("UNKNOWN", None, None)

    def _extract_cvss_v2(self, metrics: Dict) -> Tuple[Optional[float], Optional[str]]:
        """Extract CVSS v2 score and vector"""
        if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            m = metrics["cvssMetricV2"][0]
            cvss = m.get("cvssData", {})
            return (cvss.get("baseScore"), cvss.get("vectorString"))
        return (None, None)

    def get_cves_for_version(self, vendor: str, product: str, version: str) -> List[Dict]:
        """Get cached CVEs for a version"""
        rows = self.conn.execute("""
            SELECT c.* FROM cve_records c
            JOIN cpe_cve_mapping m ON c.cve_id = m.cve_id
            WHERE m.cpe_vendor = ? AND m.cpe_product = ? AND m.version_exact = ?
            ORDER BY c.cvss_v3_score DESC NULLS LAST
        """, (vendor.lower(), product.lower(), version.lower())).fetchall()
        return [dict(row) for row in rows]

    def get_version_summary(self) -> List[Dict]:
        """Get summary of all synced versions"""
        rows = self.conn.execute("""
            SELECT * FROM synced_versions ORDER BY cve_count DESC
        """).fetchall()
        return [dict(row) for row in rows]

    def get_overall_summary(self) -> Dict:
        """Get overall CVE statistics"""
        row = self.conn.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN severity='CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity='MEDIUM' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity='LOW' THEN 1 ELSE 0 END) as low
            FROM cve_records
        """).fetchone()
        return dict(row) if row else {}
