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

from relreqx.engine import admit_object, inspect_object  # noqa: E402
from relreqx.load import load_json  # noqa: E402

NOW = 1781784000  # 2026-06-18T12:00:00Z

EXPECTED = {
    "ok-same": ("allow", []),
    "ok-cors": ("allow", []),
    "bad-sig": ("deny", ["sig_invalid"]),
    "site": ("deny", ["site_mismatch"]),
    "mode": ("deny", ["mode_not_allowed"]),
    "dest": ("deny", ["dest_not_allowed"]),
    "revoked": ("deny", ["kid_revoked"]),
    "null-origin": ("deny", ["null_origin_denied"]),
    "http-downgrade": ("deny", ["http_downgrade"]),
    "case-host": ("deny", ["host_case_mismatch"]),
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sign_full_form(obj: dict, secret_hex: str) -> str:
    line = "v1|{kid}|{origin}|{referer}|{mode}|{dest}".format(
        kid=obj["kid"],
        origin=obj.get("origin", ""),
        referer=obj.get("referer", ""),
        mode=obj.get("mode", ""),
        dest=obj.get("dest", ""),
    )
    return _b64url(hmac.new(bytes.fromhex(secret_hex), line.encode("ascii"), hashlib.sha256).digest())


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
        report = self._admit("ok-same")
        self.assertEqual(set(report), {"decision", "reason_codes", "kind", "notes"})
        self.assertEqual(report["kind"], "relreqx")
        self.assertEqual(report["reason_codes"], [])
        self.assertEqual(report["notes"], [])

    def test_deny_never_mutates_store_and_allow_records_id(self) -> None:
        store = {"items": {}}
        report = self._admit("bad-sig", store=store)
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(store, {"items": {}})

        report = self._admit("ok-same", store=store)
        self.assertEqual(report["decision"], "allow")
        self.assertIn("ok-0", store["items"])
        self.assertEqual(store["items"]["ok-0"], {"ts": NOW})

        replay = self._admit("ok-same", store=store)
        self.assertEqual(replay["decision"], "deny")
        self.assertEqual(replay["reason_codes"], ["replay"])

    def test_tampered_body_fails_signature(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-same/input.json")
        obj["path"] = "/v1/relreqx/tampered"
        report = self._admit("ok-same", obj=obj)
        self.assertEqual(report["decision"], "deny")
        self.assertIn("sig_invalid", report["reason_codes"])

    def test_revoked_kid_denies_even_with_valid_hmac(self) -> None:
        report = self._admit("revoked")
        self.assertEqual(report["reason_codes"], ["kid_revoked"])

    def test_unknown_kid(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-same/input.json")
        obj["kid"] = "k-missing"
        report = self._admit("ok-same", obj=obj)
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(report["reason_codes"], ["kid_unknown"])

    def test_inspect_output_unchanged(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-same/input.json")
        summary = inspect_object(obj)
        self.assertEqual(set(summary), {"kind", "keys", "preview"})
        self.assertEqual(summary["kind"], "relreqx")
        self.assertEqual(summary["keys"], sorted(obj.keys()))

    def test_full_form_six_field_signing_line(self) -> None:
        secret = self.keys["keys"]["k-active"]["secret"]
        base = {
            "kid": "k-active",
            "origin": "https://example.com",
            "referer": "https://example.com/v1/relreqx/full",
            "mode": "cors",
            "dest": "",
        }
        obj = dict(base)
        obj["sig"] = sign_full_form(obj, secret)
        report = admit_object(copy.deepcopy(obj), copy.deepcopy(self.keys),
                              copy.deepcopy(self.policy), {"items": {}}, NOW)
        self.assertEqual(report["decision"], "allow", report)

        tampered = dict(base)
        tampered["origin"] = "https://other-site.example"
        tampered["sig"] = sign_full_form(tampered, secret)
        report = admit_object(tampered, copy.deepcopy(self.keys),
                              copy.deepcopy(self.policy), {"items": {}}, NOW)
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(report["reason_codes"], ["origin_denied", "site_mismatch"])

        navigate = dict(base)
        navigate["mode"] = "navigate"
        navigate["dest"] = "iframe"
        navigate["sig"] = sign_full_form(navigate, secret)
        report = admit_object(navigate, copy.deepcopy(self.keys),
                              copy.deepcopy(self.policy), {"items": {}}, NOW)
        self.assertEqual(report["decision"], "allow", report)

        bad_sig = dict(base)
        bad_sig["sig"] = sign_full_form(base, secret)[:-2] + "AA"
        report = admit_object(bad_sig, copy.deepcopy(self.keys),
                              copy.deepcopy(self.policy), {"items": {}}, NOW)
        self.assertIn("sig_invalid", report["reason_codes"])

    def test_full_form_gates(self) -> None:
        secret = self.keys["keys"]["k-active"]["secret"]

        def make(**overrides):
            obj = {
                "kid": "k-active",
                "origin": "https://example.com",
                "referer": "https://example.com/v1/relreqx/x",
                "mode": "cors",
                "dest": "",
            }
            obj.update(overrides)
            obj["sig"] = sign_full_form(obj, secret)
            return obj

        null_obj = make(origin="null", referer="null")
        report = self._admit("ok-same", obj=null_obj)
        self.assertEqual(report["reason_codes"], ["null_origin_denied"])

        downgrade = make(origin="http://example.com")
        report = self._admit("ok-same", obj=downgrade)
        self.assertEqual(report["reason_codes"], ["http_downgrade"])

        upper = make(origin="https://Example.COM")
        report = self._admit("ok-same", obj=upper)
        self.assertEqual(report["reason_codes"], ["host_case_mismatch"])

        bad_dest = make(mode="navigate", dest="document")
        report = self._admit("ok-same", obj=bad_dest)
        self.assertEqual(report["reason_codes"], ["dest_not_allowed"])


class CliParityTests(unittest.TestCase):
    def _run_cli(self, case: str, tmp: Path):
        report_path = tmp / f"{case}-report.json"
        store_path = tmp / f"{case}-store.json"
        proc = subprocess.run(
            [
                sys.executable, "-m", "relreqx", "admit",
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

    def test_load_failure_exit_code_two(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            proc = subprocess.run(
                [
                    sys.executable, "-m", "relreqx", "admit",
                    "--input", str(ROOT / "fixtures/cases/ok-same/input.json"),
                    "--keys", str(tmp / "missing-keys.json"),
                    "--policy", str(ROOT / "fixtures/policy.json"),
                    "--store", str(tmp / "store.json"),
                    "--now", "2026-06-18T12:00:00Z",
                    "--report", str(tmp / "report.json"),
                ],
                cwd=ROOT, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 2)
            self.assertFalse((tmp / "store.json").exists())
            self.assertFalse((tmp / "report.json").exists())


if __name__ == "__main__":
    unittest.main()
