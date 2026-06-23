#!/usr/bin/env python3
"""Unit tests for reconftw_mcp (no network, no reconftw.sh execution)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("RECONFTW_ROOT", str(ROOT))

from reconftw_mcp.functions import get_function, list_functions
from reconftw_mcp.layers import CRITICAL_LAYER_IDS, get_layer, list_layers
from reconftw_mcp.paths import find_reconftw_root
from reconftw_mcp.results import (
    get_result_paths,
    get_scan_status,
    list_report_files,
    read_ai_report,
    read_report,
    search_results,
)


class LayerRegistryTests(unittest.TestCase):
    def test_critical_layers_exist(self) -> None:
        self.assertIn("osint_quick", CRITICAL_LAYER_IDS)
        self.assertIn("web_probe", CRITICAL_LAYER_IDS)
        for lid in CRITICAL_LAYER_IDS:
            layer = get_layer(lid)
            self.assertLessEqual(layer.eta_minutes, 5)

    def test_list_layers_tier_filter(self) -> None:
        critical = list_layers(tier="critical")
        self.assertTrue(all(layer.tier == "critical" for layer in critical))
        self.assertGreaterEqual(len(critical), 5)

    def test_find_root(self) -> None:
        root = find_reconftw_root()
        self.assertTrue((root / "reconftw.sh").is_file())


class FunctionCatalogTests(unittest.TestCase):
    def test_generate_report_function_exists(self) -> None:
        fn = get_function("generate_consolidated_report")
        self.assertEqual(fn.category, "report")

    def test_list_functions_by_category(self) -> None:
        osint = list_functions(category="osint")
        self.assertTrue(all(fn.category == "osint" for fn in osint))
        self.assertTrue(any(fn.name == "domain_info" for fn in osint))


class ResultsTests(unittest.TestCase):
    def _make_scan(self, root: Path, domain: str) -> Path:
        scan = root / "Recon" / domain
        (scan / "osint").mkdir(parents=True)
        (scan / "osint" / "emails.txt").write_text("admin@example.com\n", encoding="utf-8")
        return scan

    def test_search_and_paths_on_temp_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reconftw.sh").write_text("# stub\n", encoding="utf-8")
            os.environ["RECONFTW_ROOT"] = str(root)
            domain = "example.com"
            self._make_scan(root, domain)

            status = get_scan_status(domain)
            self.assertEqual(status["domain"], domain)

            hits = search_results(domain, "admin@")
            self.assertEqual(len(hits), 1)
            paths = get_result_paths(domain)
            self.assertTrue(any("emails.txt" in p.relative for p in paths))

    def test_read_report_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reconftw.sh").write_text("# stub\n", encoding="utf-8")
            os.environ["RECONFTW_ROOT"] = str(root)
            domain = "example.com"
            scan = self._make_scan(root, domain)
            report = {
                "domain": domain,
                "summary": {"subdomains": 10, "webs": 5},
                "severities": {"critical": 1},
            }
            (scan / "report").mkdir()
            (scan / "report" / "report.json").write_text(json.dumps(report), encoding="utf-8")

            body = read_report(domain, "summary")
            payload = json.loads(body)
            self.assertEqual(payload["summary"]["subdomains"], 10)

            files = list_report_files(domain)
            self.assertTrue(any(f.relative == "report/report.json" and f.exists for f in files))

    def test_read_ai_report_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reconftw.sh").write_text("# stub\n", encoding="utf-8")
            os.environ["RECONFTW_ROOT"] = str(root)
            domain = "example.com"
            self._make_scan(root, domain)
            body = read_ai_report(domain)
            self.assertIn("No AI report found", body)


if __name__ == "__main__":
    unittest.main()
