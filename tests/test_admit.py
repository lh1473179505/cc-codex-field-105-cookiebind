from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fuzzcrash.engine import admit_object, inspect_object  # noqa: E402
from fuzzcrash.load import load_json  # noqa: E402

NOW = 1781784000  # 2026-06-18T12:00:00Z

EXPECTED = {
    "ok-segv": ("allow", []),
    "ok-abrt": ("allow", []),
    "bad-sig": ("deny", ["sig_invalid"]),
    "stack": ("deny", ["stack_invalid"]),
    "fault": ("deny", ["fault_denied"]),
    "sev": ("deny", ["severity_denied"]),
    "dup": ("deny", ["duplicate"]),
    "revoked": ("deny", ["kid_revoked"]),
    "trunc-stack": ("deny", ["stack_truncated"]),
    "raw-addr": ("deny", ["raw_addr"]),
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _sign(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("ascii"), hashlib.sha256).digest()
    return _b64url(digest)


def _full_form_ticket(secret_hex: str, **overrides) -> dict:
    obj = {
        "id": "full-0",
        "kid": "k-active",
        "stack": ["#0 0x7f01 in crash_handler", "#1 0x7f02 in main"],
        "fault": "SEGV",
        "severity": "high",
    }
    obj.update(overrides)
    norm = "\n".join(re.sub(r"0x[0-9a-fA-F]+", "0x0", frame) for frame in obj["stack"])
    sha = hashlib.sha256(norm.encode("utf-8")).hexdigest()
    line = "v1|{kid}|{sha}|{fault}|{severity}".format(
        kid=obj["kid"], sha=sha, fault=obj["fault"], severity=obj["severity"]
    )
    obj["sig"] = _sign(secret_hex, line)
    return obj


class AdmitFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = load_json(ROOT / "fixtures/keys.json")
        self.policy = load_json(ROOT / "fixtures/policy.json")

    def _admit(self, case: str, obj=None, store=None, policy=None):
        if obj is None:
            obj = load_json(ROOT / f"fixtures/cases/{case}/input.json")
        return admit_object(
            copy.deepcopy(obj),
            copy.deepcopy(self.keys),
            copy.deepcopy(policy if policy is not None else self.policy),
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
        report = self._admit("ok-segv")
        self.assertEqual(set(report), {"decision", "reason_codes", "kind", "notes"})
        self.assertEqual(report["kind"], "fuzzcrash")
        self.assertEqual(report["reason_codes"], [])

    def test_deny_never_mutates_store_and_allow_records_bucket(self) -> None:
        store = {"items": {}}
        report = self._admit("bad-sig", store=store)
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(store, {"items": {}})

        report = self._admit("ok-segv", store=store)
        self.assertEqual(report["decision"], "allow")
        self.assertIn("ok-0", store["items"])
        replay = self._admit("ok-segv", store=store)
        self.assertEqual(replay["reason_codes"], ["duplicate"])

    def test_tampered_body_fails_signature(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-segv/input.json")
        obj["path"] = "/evil/fuzzcrash/tampered"
        report = self._admit("ok-segv", obj=obj)
        self.assertEqual(report["decision"], "deny")
        self.assertIn("sig_invalid", report["reason_codes"])

    def test_revoked_kid_denies_even_with_valid_hmac(self) -> None:
        report = self._admit("revoked")
        self.assertEqual(report["reason_codes"], ["kid_revoked"])

    def test_inspect_output_unchanged(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-segv/input.json")
        summary = inspect_object(obj)
        self.assertEqual(set(summary), {"kind", "keys", "preview"})
        self.assertEqual(summary["kind"], "fuzzcrash")


class FullFormTests(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = load_json(ROOT / "fixtures/keys.json")
        self.policy = load_json(ROOT / "fixtures/policy.json")
        self.secret = self.keys["keys"]["k-active"]["secret"]

    def _admit(self, obj, policy=None, store=None):
        return admit_object(
            copy.deepcopy(obj),
            copy.deepcopy(self.keys),
            copy.deepcopy(policy if policy is not None else self.policy),
            store if store is not None else {"items": {}},
            NOW,
        )

    def test_full_form_allow(self) -> None:
        report = self._admit(_full_form_ticket(self.secret))
        self.assertEqual(report["decision"], "allow")
        self.assertEqual(report["reason_codes"], [])

    def test_full_form_bad_sig(self) -> None:
        obj = _full_form_ticket(self.secret)
        obj["sig"] = _sign(self.secret, "v1|k-active|0|SEGV|high")
        report = self._admit(obj)
        self.assertIn("sig_invalid", report["reason_codes"])

    def test_full_form_aslr_normalization(self) -> None:
        # Same frames at different load addresses hash identically.
        obj = _full_form_ticket(self.secret)
        moved = _full_form_ticket(
            self.secret,
            stack=["#0 0xdead in crash_handler", "#1 0xbeef in main"],
        )
        self.assertEqual(obj["sig"], moved["sig"])

    def test_full_form_truncated_stack(self) -> None:
        obj = _full_form_ticket(self.secret, stack=["#0 0x7f01 in main"])
        report = self._admit(obj)
        self.assertIn("stack_truncated", report["reason_codes"])

    def test_full_form_fault_gate(self) -> None:
        obj = _full_form_ticket(self.secret, fault="WILD")
        report = self._admit(obj)
        self.assertIn("fault_denied", report["reason_codes"])

    def test_full_form_severity_gate(self) -> None:
        obj = _full_form_ticket(self.secret, severity="low")
        report = self._admit(obj, policy={"min_severity": "high"})
        self.assertIn("severity_denied", report["reason_codes"])


class CliParityTests(unittest.TestCase):
    def _run_cli(self, case: str, tmp: Path):
        report_path = tmp / f"{case}-report.json"
        store_path = tmp / f"{case}-store.json"
        proc = subprocess.run(
            [
                sys.executable, "-m", "fuzzcrash", "admit",
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
        store_exists = store_path.exists()
        store = load_json(store_path) if store_exists else None
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


if __name__ == "__main__":
    unittest.main()
