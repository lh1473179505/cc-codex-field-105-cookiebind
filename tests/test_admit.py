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

from pasetox.engine import TOKEN_VERSION, admit_object, inspect_object  # noqa: E402
from pasetox.load import load_json  # noqa: E402

NOW = 1781784000  # 2026-06-18T12:00:00Z

EXPECTED = {
    "ok-basic": ("allow", []),
    "ok-footer": ("allow", []),
    "bad-sig": ("deny", ["sig_invalid"]),
    "ver": ("deny", ["version_rejected"]),
    "footer": ("deny", ["footer_tenant_denied"]),
    "implicit": ("deny", ["implicit_assertion_mismatch"]),
    "aud": ("deny", ["aud_denied"]),
    "revoked": ("deny", ["kid_revoked"]),
    "kid-ver": ("deny", ["kid_version_denied"]),
    "payload": ("deny", ["sub_denied"]),
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


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
        report = self._admit("ok-basic")
        self.assertEqual(set(report), {"decision", "reason_codes", "kind", "notes"})
        self.assertEqual(report["kind"], "pasetox")
        self.assertEqual(report["reason_codes"], [])
        self.assertEqual(report["notes"], [])

    def test_deny_never_mutates_store_and_allow_records_id(self) -> None:
        store = {"items": {}}
        report = self._admit("bad-sig", store=store)
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(store, {"items": {}})

        report = self._admit("ok-basic", store=store)
        self.assertEqual(report["decision"], "allow")
        self.assertIn("ok-0", store["items"])
        replay = self._admit("ok-basic", store=store)
        self.assertEqual(replay["reason_codes"], ["replay"])

    def test_tampered_body_fails_signature(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-basic/input.json")
        obj["path"] = "/v1/pasetox/tampered"
        report = self._admit("ok-basic", obj=obj)
        self.assertEqual(report["decision"], "deny")
        self.assertIn("sig_invalid", report["reason_codes"])

    def test_revoked_kid_denies_even_with_valid_hmac(self) -> None:
        report = self._admit("revoked")
        self.assertEqual(report["reason_codes"], ["kid_revoked"])

        # A freshly minted, HMAC-valid token under the revoked kid still denies.
        secret = bytes.fromhex(self.keys["keys"]["k-revoked"]["secret"])
        body = {"case": "x", "id": "rev-1", "marker": "allow-candidate", "path": "/v1/pasetox/x"}
        digest = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        sig = _b64url(hmac.new(secret, f"v1|k-revoked|{digest}".encode(), hashlib.sha256).digest())
        token = dict(body, kid="k-revoked", sig=sig)
        report = self._admit("revoked", obj=token)
        self.assertEqual(report["reason_codes"], ["kid_revoked"])

    def test_unknown_kid(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-basic/input.json")
        obj["kid"] = "k-missing"
        obj["id"] = "unk-1"
        report = self._admit("ok-basic", obj=obj)
        self.assertIn("kid_unknown", report["reason_codes"])

    def test_full_form_v4_local_signing_input(self) -> None:
        secret = bytes.fromhex(self.keys["keys"]["k-active"]["secret"])
        token = {
            "version": TOKEN_VERSION,
            "id": "full-1",
            "footer": json.dumps({"tenant": "tenant-a"}, separators=(",", ":")),
            "implicit_assertion": "ctx-default",
            "aud": "pasetox-api",
            "sub": "subject-0",
            "data": "hello",
            "kid": "k-active",
        }
        body = {k: v for k, v in token.items() if k not in ("kid", "sig", "_sign_line")}
        payload_sha = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        footer_sha = hashlib.sha256(token["footer"].encode()).hexdigest()
        implicit_sha = hashlib.sha256(token["implicit_assertion"].encode()).hexdigest()
        line = f"{TOKEN_VERSION}|k-active|{payload_sha}|{footer_sha}|{implicit_sha}"
        token["sig"] = _b64url(hmac.new(secret, line.encode(), hashlib.sha256).digest())
        report = self._admit("full", obj=token)
        self.assertEqual(report["decision"], "allow")

        token["version"] = "v3.local"
        token["id"] = "full-2"
        report = self._admit("full", obj=token)
        self.assertIn("version_rejected", report["reason_codes"])

    def test_inspect_output_unchanged(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-basic/input.json")
        summary = inspect_object(obj)
        self.assertEqual(set(summary), {"kind", "keys", "preview"})
        self.assertEqual(summary["kind"], "pasetox")


class CliParityTests(unittest.TestCase):
    def _run_cli(self, case: str, tmp: Path):
        report_path = tmp / f"{case}-report.json"
        store_path = tmp / f"{case}-store.json"
        proc = subprocess.run(
            [
                sys.executable, "-m", "pasetox", "admit",
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
