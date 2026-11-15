from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sfkeyx.engine import admit_object, canonical_dictionary, inspect_object  # noqa: E402
from sfkeyx.load import load_json  # noqa: E402

NOW = 1781784000  # 2026-06-18T12:00:00Z

EXPECTED = {
    "ok-dict": ("allow", []),
    "ok-params": ("allow", []),
    "bad-sig": ("deny", ["bad_signature"]),
    "order": ("deny", ["key_order_invalid"]),
    "type": ("deny", ["type_marker_invalid"]),
    "param": ("deny", ["param_order_invalid"]),
    "revoked": ("deny", ["kid_revoked"]),
    "dup-key": ("deny", ["duplicate_key"]),
    "float": ("deny", ["float_not_allowed"]),
    "empty": ("deny", ["empty_payload"]),
}


class AdmitFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = load_json(ROOT / "fixtures/keys.json")
        self.policy = load_json(ROOT / "fixtures/policy.json")

    def _admit(self, case: str, obj=None, store=None):
        if obj is None:
            obj = load_json(ROOT / f"fixtures/cases/{case}/input.json")
        return admit_object(
            copy.deepcopy(obj),
            copy.deepcopy(self.keys),
            copy.deepcopy(self.policy),
            store if store is not None else {"items": {}},
            NOW,
        )

    def test_every_fixture_matches_documented_gate(self) -> None:
        for case, (decision, codes) in EXPECTED.items():
            with self.subTest(case=case):
                report = self._admit(case)
                self.assertEqual(report["decision"], decision)
                self.assertEqual(report["reason_codes"], codes)

    def test_report_shape(self) -> None:
        report = self._admit("ok-dict")
        self.assertEqual(set(report), {"decision", "reason_codes", "kind", "notes"})
        self.assertEqual(report["kind"], "sfkeyx")
        self.assertEqual(report["reason_codes"], [])

    def test_deny_never_mutates_store_and_allow_records_id(self) -> None:
        store = {"items": {}}
        report = self._admit("bad-sig", store=store)
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(store, {"items": {}})

        report = self._admit("ok-dict", store=store)
        self.assertEqual(report["decision"], "allow")
        self.assertIn("ok-0", store["items"])
        self.assertEqual(store["items"]["ok-0"]["ts"], NOW)

    def test_tampered_body_fails_signature(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-dict/input.json")
        obj["path"] = "/v1/sfkeyx/tampered"
        report = self._admit("ok-dict", obj=obj)
        self.assertEqual(report["decision"], "deny")
        self.assertIn("bad_signature", report["reason_codes"])

    def test_revoked_kid_denies_even_with_valid_hmac(self) -> None:
        report = self._admit("revoked")
        self.assertEqual(report["reason_codes"], ["kid_revoked"])

    def test_unknown_kid(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-dict/input.json")
        obj["kid"] = "missing-kid"
        report = self._admit("ok-dict", obj=obj)
        self.assertEqual(report["decision"], "deny")
        self.assertIn("kid_unknown", report["reason_codes"])

    def test_structural_rules_are_enforced_on_content(self) -> None:
        base = load_json(ROOT / "fixtures/cases/ok-dict/input.json")
        float_obj = copy.deepcopy(base)
        float_obj["ratio"] = 1.5
        self.assertIn("float_not_allowed", self._admit("ok-dict", obj=float_obj)["reason_codes"])

        none_obj = copy.deepcopy(base)
        none_obj["maybe"] = None
        self.assertIn("type_marker_invalid", self._admit("ok-dict", obj=none_obj)["reason_codes"])

    def test_canonical_dictionary_sorts_keys_and_strips_envelope(self) -> None:
        obj_a = {"b": 1, "a": "x", "kid": "k", "sig": "s", "_sign_line": "l"}
        obj_b = {"a": "x", "b": 1, "kid": "k", "sig": "s", "_sign_line": "l"}
        self.assertEqual(canonical_dictionary(obj_a), canonical_dictionary(obj_b))
        self.assertEqual(canonical_dictionary(obj_a), '{"a":"x","b":1}')

    def test_inspect_output_unchanged(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-dict/input.json")
        summary = inspect_object(obj)
        self.assertEqual(set(summary), {"kind", "keys", "preview"})
        self.assertEqual(summary["kind"], "sfkeyx")
        self.assertEqual(summary["keys"], sorted(obj.keys()))


class CliParityTests(unittest.TestCase):
    def _run_cli(self, case: str, tmp: Path):
        report_path = tmp / f"{case}-report.json"
        store_path = tmp / f"{case}-store.json"
        proc = subprocess.run(
            [
                sys.executable, "-m", "sfkeyx", "admit",
                "--input", str(ROOT / f"fixtures/cases/{case}/input.json"),
                "--keys", str(ROOT / "fixtures/keys.json"),
                "--policy", str(ROOT / "fixtures/policy.json"),
                "--store", str(store_path),
                "--now", "2026-06-18T12:00:00Z",
                "--report", str(report_path),
            ],
            cwd=ROOT, capture_output=True, text=True,
        )
        report = json.loads(report_path.read_text(encoding="utf-8"))
        store = load_json(store_path) if store_path.exists() else None
        return proc.returncode, report, store

    def test_cli_matches_library_for_every_fixture(self) -> None:
        keys = load_json(ROOT / "fixtures/keys.json")
        policy = load_json(ROOT / "fixtures/policy.json")
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            for case, (decision, codes) in EXPECTED.items():
                with self.subTest(case=case):
                    obj = load_json(ROOT / f"fixtures/cases/{case}/input.json")
                    lib = admit_object(
                        copy.deepcopy(obj), copy.deepcopy(keys),
                        copy.deepcopy(policy), {"items": {}}, NOW,
                    )
                    rc, cli_report, store = self._run_cli(case, tmp)
                    self.assertEqual(cli_report["decision"], lib["decision"])
                    self.assertEqual(cli_report["reason_codes"], lib["reason_codes"])
                    self.assertEqual(cli_report["decision"], decision)
                    self.assertEqual(cli_report["reason_codes"], codes)
                    if decision == "allow":
                        self.assertEqual(rc, 0)
                        self.assertIsNotNone(store)
                        self.assertIn(obj.get("id"), store["items"])
                    else:
                        self.assertEqual(rc, 1)
                        self.assertIsNone(store)

    def test_load_failure_exits_two_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            store_path = tmp / "store.json"
            store_path.write_text('{"items": {}}', encoding="utf-8")
            report_path = tmp / "report.json"
            proc = subprocess.run(
                [
                    sys.executable, "-m", "sfkeyx", "admit",
                    "--input", str(tmp / "missing.json"),
                    "--keys", str(ROOT / "fixtures/keys.json"),
                    "--policy", str(ROOT / "fixtures/policy.json"),
                    "--store", str(store_path),
                    "--now", "2026-06-18T12:00:00Z",
                    "--report", str(report_path),
                ],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertFalse(report_path.exists())
            self.assertEqual(store_path.read_text(encoding="utf-8"), '{"items": {}}')


if __name__ == "__main__":
    unittest.main()
