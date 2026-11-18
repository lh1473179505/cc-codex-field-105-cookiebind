"""Combination and compatibility tests for the two writer paths."""
from __future__ import annotations

import unittest

from trivyconf.mixed_case import run_combination
from trivyconf.orchestrator import ScanService


class ConvergenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = run_combination()

    def test_snapshot_delta_recovery_converges(self) -> None:
        self.assertEqual([], self.result["problems"])

    def test_recovery_keeps_target_isolation(self) -> None:
        items = {row["scope"] + ":" + row["id"]: row for row in self.result["second"]["items"]}
        self.assertEqual("recovered", items["shadow:item"]["value"])
        self.assertEqual(2, items["shadow:item"]["generation"])
        self.assertNotIn("main:item", items)
        self.assertEqual(["main:ghost"], self.result["second"]["revoked"])

    def test_cache_reuse_cannot_override_snapshot_row(self) -> None:
        service = ScanService()
        service.snapshot(generation=1, sequence=10, rows=[
            {"key": "item", "scope": "main", "fingerprint": "fp-item", "value": "old"},
        ])
        service.snapshot(generation=2, sequence=20, rows=[
            {"key": "item", "scope": "main", "fingerprint": "fp-item", "value": "new"},
        ])
        items = service.report()["items"]
        self.assertEqual(1, len(items))
        self.assertEqual("new", items[0]["value"])
        self.assertEqual(2, items[0]["generation"])

    def test_both_write_paths_reach_shared_journal(self) -> None:
        service = self.result["service"]
        kinds = [entry["kind"] for entry in service.journal.entries()]
        self.assertIn("snapshot", kinds)
        self.assertIn("delta", kinds)
        self.assertGreaterEqual(service.state.generation, 1)

    def test_late_result_cannot_cross_recovery(self) -> None:
        self.assertFalse(self.result["late"]["accepted"])
        self.assertFalse(any(row["id"] == "ghost" for row in self.result["second"]["items"]))

    def test_legacy_report_is_repeatable_and_read_only(self) -> None:
        self.assertEqual(self.result["before"], self.result["after_first"])
        self.assertEqual(self.result["before"], self.result["after_second"])
        self.assertEqual("scan-v1", self.result["second"]["schema"])

    def test_audit_keeps_operation_history(self) -> None:
        before = self.result["service"].state_token()
        audit = self.result["service"].audit()
        self.assertEqual("audit-v1", audit["schema"])
        self.assertTrue(audit["operations"])
        self.assertEqual(before, self.result["service"].state_token())
