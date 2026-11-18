"""Combination and compatibility tests for the two writer paths."""
from __future__ import annotations

import unittest

from nucleix.recovery_flow import run_combination


class ConvergenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = run_combination()

    def test_snapshot_delta_recovery_converges(self) -> None:
        self.assertEqual([], self.result["problems"])

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
        self.assertEqual(self.result["first"]["items"], self.result["second"]["items"])
        item = next(row for row in self.result["second"]["items"] if row["id"] == "item")
        self.assertEqual("recovered", item["value"])

    def test_audit_is_repeatable_and_read_only(self) -> None:
        service = self.result["service"]
        before = service.state_token()
        first = service.audit()
        second = service.audit()
        self.assertEqual(first, second)
        self.assertEqual(before, service.state_token())
        self.assertEqual(self.result["before"], self.result["after_audit"])

    def test_audit_keeps_operation_history(self) -> None:
        before = self.result["service"].state_token()
        audit = self.result["service"].audit()
        self.assertEqual("audit-v1", audit["schema"])
        self.assertTrue(audit["operations"])
        self.assertEqual(before, self.result["service"].state_token())
