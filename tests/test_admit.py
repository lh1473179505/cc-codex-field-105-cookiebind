from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from samlbind.engine import admit_object, inspect_object, signing_input  # noqa: E402
from samlbind.load import load_json  # noqa: E402

NOW = 1781784000  # 2026-06-18T12:00:00Z

EXPECTED = {
    "ok-sso": ("allow", []),
    "ok-skew": ("allow", []),
    "bad-sig": ("deny", ["bad_signature"]),
    "aud": ("deny", ["audience_mismatch"]),
    "recipient": ("deny", ["recipient_mismatch"]),
    "expired": ("deny", ["expired"]),
    "issuer": ("deny", ["issuer_mismatch"]),
    "revoked": ("deny", ["kid_revoked"]),
    "skew": ("deny", ["clock_skew_exceeded"]),
    "empty-aud": ("deny", ["audience_mismatch"]),
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
        report = self._admit("ok-sso")
        self.assertEqual(set(report), {"decision", "reason_codes", "kind", "notes"})
        self.assertEqual(report["kind"], "samlbind")
        self.assertEqual(report["reason_codes"], [])
        self.assertEqual(report["notes"], [])

    def test_deny_never_mutates_store_and_allow_records_id(self) -> None:
        store = {"items": {}}
        report = self._admit("bad-sig", store=store)
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(store, {"items": {}})

        report = self._admit("ok-sso", store=store)
        self.assertEqual(report["decision"], "allow")
        self.assertIn("ok-0", store["items"])
        replay = self._admit("ok-sso", store=store)
        self.assertEqual(replay["reason_codes"], ["replay"])

    def test_revoked_kid_denies_even_with_valid_hmac(self) -> None:
        report = self._admit("revoked")
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(report["reason_codes"], ["kid_revoked"])

    def test_tampered_body_fails_signature(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-sso/input.json")
        obj["path"] = "/v1/samlbind/tampered"
        report = self._admit("ok-sso", obj=obj)
        self.assertEqual(report["decision"], "deny")
        self.assertIn("bad_signature", report["reason_codes"])

    def test_unknown_kid(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-sso/input.json")
        obj["kid"] = "k-ghost"
        report = self._admit("ok-sso", obj=obj)
        self.assertEqual(report["decision"], "deny")
        self.assertIn("kid_unknown", report["reason_codes"])

    def test_invalid_store_raises(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-sso/input.json")
        with self.assertRaises(ValueError):
            admit_object(
                copy.deepcopy(obj),
                copy.deepcopy(self.keys),
                copy.deepcopy(self.policy),
                {"nope": {}},
                NOW,
            )

    def test_inspect_output_unchanged(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-sso/input.json")
        summary = inspect_object(obj)
        self.assertEqual(set(summary), {"kind", "keys", "preview"})
        self.assertEqual(summary["kind"], "samlbind")


class FullFormTests(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = load_json(ROOT / "fixtures/keys.json")
        self.policy = {
            "clock_skew_seconds": 60,
            "allowed_issuers": ["https://idp.example/saml"],
            "allowed_audiences": ["https://sp.example/acs"],
            "allowed_recipients": ["https://sp.example/acs"],
        }

    def _sign(self, obj: dict) -> dict:
        obj = copy.deepcopy(obj)
        secret = bytes.fromhex(self.keys["keys"]["k-active"]["secret"])
        line = signing_input(obj)
        obj["sig"] = base64.urlsafe_b64encode(
            hmac.new(secret, line.encode("ascii"), hashlib.sha256).digest()
        ).rstrip(b"=").decode("ascii")
        return obj

    def _base(self, not_on_or_after: int) -> dict:
        return {
            "case": "full",
            "id": "full-0",
            "kid": "k-active",
            "issuer": "https://idp.example/saml",
            "audience": "https://sp.example/acs",
            "recipient": "https://sp.example/acs",
            "not_on_or_after": not_on_or_after,
        }

    def test_full_form_allow_and_gates(self) -> None:
        obj = self._sign(self._base(NOW + 300))
        report = admit_object(obj, copy.deepcopy(self.keys), self.policy, {"items": {}}, NOW)
        self.assertEqual((report["decision"], report["reason_codes"]), ("allow", []))

        bad_aud = self._sign({**self._base(NOW + 300), "audience": "https://evil.example"})
        report = admit_object(bad_aud, copy.deepcopy(self.keys), self.policy, {"items": {}}, NOW)
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(report["reason_codes"], ["audience_mismatch"])

        tampered = self._sign(self._base(NOW + 300))
        tampered["recipient"] = "https://evil.example/acs"
        report = admit_object(tampered, copy.deepcopy(self.keys), self.policy, {"items": {}}, NOW)
        self.assertIn("bad_signature", report["reason_codes"])
        self.assertIn("recipient_mismatch", report["reason_codes"])

    def test_full_form_expiry_with_skew(self) -> None:
        within_skew = self._sign(self._base(NOW - 60))
        report = admit_object(within_skew, copy.deepcopy(self.keys), self.policy, {"items": {}}, NOW)
        self.assertEqual(report["decision"], "allow")

        expired = self._sign(self._base(NOW - 61))
        report = admit_object(expired, copy.deepcopy(self.keys), self.policy, {"items": {}}, NOW)
        self.assertEqual(report["reason_codes"], ["expired"])

    def test_full_form_empty_audience_denies(self) -> None:
        obj = self._sign({**self._base(NOW + 300), "audience": ""})
        report = admit_object(obj, copy.deepcopy(self.keys), self.policy, {"items": {}}, NOW)
        self.assertIn("audience_mismatch", report["reason_codes"])


class CliParityTests(unittest.TestCase):
    def _run_cli(self, case: str, tmp: Path):
        report_path = tmp / f"{case}-report.json"
        store_path = tmp / f"{case}-store.json"
        store_path.write_text(json.dumps({"items": {}}), encoding="utf-8")
        proc = subprocess.run(
            [
                sys.executable, "-m", "samlbind", "admit",
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
        store = json.loads(store_path.read_text(encoding="utf-8"))
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
                        self.assertIn(obj["id"], store["items"])
                    else:
                        self.assertEqual(rc, 1)
                        self.assertEqual(store, {"items": {}})


if __name__ == "__main__":
    unittest.main()
