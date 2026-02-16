"""Secure Cartography - Security Workers.

Background QThread workers for NVD synchronization.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional, Dict

from PyQt6.QtCore import QThread, pyqtSignal

from sc2.scng.constants import NVD_MAX_PARALLEL_WORKERS, NVD_RATE_LIMIT_DELAY
from .platform_parser import ParsedPlatform
from .cve_cache import CVECache


class SyncWorker(QThread):
    """Background worker for NVD sync operations.

    When an API key is provided, syncs are parallelized across multiple
    threads (up to NVD_MAX_PARALLEL_WORKERS) for faster throughput.
    Without an API key, syncs are sequential with longer rate-limit delays.
    """

    progress = pyqtSignal(int, int, str)  # current, total, message
    version_complete = pyqtSignal(str, dict)  # raw_platform, result
    finished_all = pyqtSignal(dict)  # summary

    def __init__(self, db_path: Path, platforms: List[ParsedPlatform],
                 api_key: Optional[str] = None, delay: float = 6.0):
        super().__init__()
        self.db_path = db_path  # Store path, create connection in run()
        self.platforms = platforms
        self.api_key = api_key
        self.delay = delay if not api_key else NVD_RATE_LIMIT_DELAY
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        total = len(self.platforms)
        results = {"synced": 0, "errors": 0, "total_cves": 0}

        if self.api_key and total > 1:
            self._run_parallel(results, total)
        else:
            self._run_sequential(results, total)

        self.finished_all.emit(results)

    def _run_sequential(self, results: Dict, total: int):
        """Sequential sync - used without API key due to strict rate limits."""
        cache = CVECache(self.db_path)
        try:
            for i, p in enumerate(self.platforms):
                if self._stop:
                    break

                self.progress.emit(i + 1, total, f"Syncing {p.cpe_vendor}:{p.cpe_product}:{p.cpe_version}")

                result = cache.sync_version(p.cpe_vendor, p.cpe_product, p.cpe_version, self.api_key)

                if "error" in result:
                    results["errors"] += 1
                    self.version_complete.emit(p.raw, {"status": "error", **result})
                else:
                    results["synced"] += 1
                    results["total_cves"] += result.get("cve_count", 0)
                    self.version_complete.emit(p.raw, {"status": "synced", **result})

                # Rate limiting delay
                if i < total - 1 and not self._stop:
                    time.sleep(self.delay)
        finally:
            cache.close()

    def _run_parallel(self, results: Dict, total: int):
        """Parallel sync - used with API key for faster throughput."""
        completed = 0
        workers = min(NVD_MAX_PARALLEL_WORKERS, total)

        def sync_one(platform: ParsedPlatform) -> tuple:
            """Sync a single platform in a worker thread."""
            # Each thread gets its own SQLite connection
            cache = CVECache(self.db_path)
            try:
                result = cache.sync_version(
                    platform.cpe_vendor, platform.cpe_product,
                    platform.cpe_version, self.api_key
                )
                # Small delay even with API key to respect rate limits
                time.sleep(self.delay)
                return (platform, result)
            finally:
                cache.close()

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {}
            for p in self.platforms:
                if self._stop:
                    break
                future = executor.submit(sync_one, p)
                futures[future] = p

            for future in as_completed(futures):
                if self._stop:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                platform, result = future.result()
                completed += 1

                self.progress.emit(
                    completed, total,
                    f"Synced {platform.cpe_vendor}:{platform.cpe_product}:{platform.cpe_version}"
                )

                if "error" in result:
                    results["errors"] += 1
                    self.version_complete.emit(platform.raw, {"status": "error", **result})
                else:
                    results["synced"] += 1
                    results["total_cves"] += result.get("cve_count", 0)
                    self.version_complete.emit(platform.raw, {"status": "synced", **result})
