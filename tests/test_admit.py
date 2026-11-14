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

from sealedbox.engine import admit_object, inspect_object  # noqa: E402
from sealedbox.load import load_json  # noqa: E402

NOW = 1781784000  # 2026-06-18T12:00:00Z

EXPECTED = {
    "ok-msg": ("allow", []),
    "ok-aad": ("allow", []),
    "bad-unseal": ("deny", ["bad_unseal"]),
    "epoch": ("deny", ["epoch_mismatch"]),
    "aad": ("deny", ["bad_unseal"]),
    "revoked": ("deny", ["kid_revoked"]),
    "short": ("deny", ["cipher_too_short"]),
    "wrong-recipient": ("deny", ["wrong_recipient"]),
    "pretty-aad": ("deny", ["bad_unseal"]),
    "future-epoch": ("deny", ["epoch_mismatch"]),
}


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
        report = self._admit("ok-msg")
        self.assertEqual(set(report), {"decision", "reason_codes", "kind", "notes"})
        self.assertEqual(report["kind"], "sealedbox")
        self.assertEqual(report["reason_codes"], [])
        self.assertEqual(report["notes"], [])

    def test_deny_never_mutates_store_and_allow_records_id(self) -> None:
        store = {"items": {}}
        report = self._admit("bad-unseal", store=store)
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(store, {"items": {}})

        report = self._admit("ok-msg", store=store)
        self.assertEqual(report["decision"], "allow")
        self.assertIn("ok-0", store["items"])
        replay = self._admit("ok-msg", store=store)
        self.assertEqual(replay["decision"], "deny")
        self.assertEqual(replay["reason_codes"], ["replay"])

    def test_tampered_body_fails_with_indistinguishable_bad_unseal(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-msg/input.json")
        obj["path"] = "/v1/sealedbox/tampered"
        report = self._admit("ok-msg", obj=obj)
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(report["reason_codes"], ["bad_unseal"])

    def test_revoked_kid_denies_even_with_valid_hmac(self) -> None:
        report = self._admit("revoked")
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(report["reason_codes"], ["kid_revoked"])

    def test_unknown_kid(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-msg/input.json")
        obj["kid"] = "does-not-exist"
        report = self._admit("ok-msg", obj=obj)
        self.assertEqual(report["reason_codes"], ["unknown_kid", "bad_unseal"])

    def test_inspect_output_unchanged(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-msg/input.json")
        summary = inspect_object(obj)
        self.assertEqual(set(summary), {"kind", "keys", "preview"})
        self.assertEqual(summary["kind"], "sealedbox")
        self.assertEqual(summary["keys"], sorted(obj.keys()))


class FullFormTests(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = load_json(ROOT / "fixtures/keys.json")
        self.secret_hex = self.keys["keys"]["k-active"]["secret"]
        self.policy = {"clock_skew_seconds": 60, "min_cipher_bytes": 16}

    def _box(self, aad=b"aad", cipher=b"x" * 32, epoch=NOW, kid="k-active",
             tamper_aad=False, tamper_sig=False, recipient=None, bad_b64=False):
        aad_sha = hashlib.sha256(aad).hexdigest()
        cipher_sha = hashlib.sha256(cipher).hexdigest()
        line = f"v1|{kid}|{epoch}|{aad_sha}|{cipher_sha}"
        secret = bytes.fromhex(self.keys["keys"][kid]["secret"])
        sig = base64.urlsafe_b64encode(
            hmac.new(secret, line.encode("ascii"), hashlib.sha256).digest()
        ).rstrip(b"=").decode("ascii")
        if tamper_sig:
            sig = "A" + sig[1:]
        obj = {
            "id": "full-1",
            "kid": kid,
            "sig": sig,
            "epoch": epoch,
            "aad_b64": base64.b64encode(b"other" if tamper_aad else aad).decode("ascii"),
            "aad_sha": aad_sha,
            "cipher_b64": "###" if bad_b64 else base64.b64encode(cipher).decode("ascii"),
            "cipher_sha": cipher_sha,
        }
        if recipient is not None:
            obj["recipient"] = recipient
        return obj

    def _admit(self, obj, keys=None, policy=None):
        return admit_object(
            copy.deepcopy(obj),
            copy.deepcopy(keys if keys is not None else self.keys),
            copy.deepcopy(policy if policy is not None else self.policy),
            {"items": {}},
            NOW,
        )

    def test_full_form_allow_and_each_gate(self) -> None:
        self.assertEqual(self._admit(self._box())["decision"], "allow")
        self.assertEqual(self._admit(self._box(tamper_aad=True))["reason_codes"], ["bad_unseal"])
        self.assertEqual(self._admit(self._box(tamper_sig=True))["reason_codes"], ["bad_unseal"])
        self.assertEqual(self._admit(self._box(bad_b64=True))["reason_codes"], ["bad_unseal", "cipher_too_short"])
        self.assertEqual(
            self._admit(self._box(cipher=b"x" * 8))["reason_codes"], ["cipher_too_short"]
        )
        self.assertEqual(
            self._admit(self._box(recipient="k-revoked"))["reason_codes"], ["wrong_recipient"]
        )
        self.assertEqual(
            self._admit(self._box(kid="k-revoked"))["reason_codes"], ["kid_revoked"]
        )

    def test_epoch_modes(self) -> None:
        window_keys = {
            "keys": {
                "k-active": {
                    "secret": self.secret_hex,
                    "status": "active",
                    "not_before": NOW - 3600,
                    "not_after": NOW + 3600,
                }
            }
        }
        self.assertEqual(self._admit(self._box(), window_keys)["reason_codes"], [])
        self.assertEqual(
            self._admit(self._box(epoch=NOW + 7200), window_keys)["reason_codes"],
            ["epoch_mismatch"],
        )
        self.assertEqual(
            self._admit(self._box(epoch=NOW + 3660), window_keys)["reason_codes"],
            [],
        )
        match_keys = {
            "keys": {"k-active": {"secret": self.secret_hex, "status": "active", "epoch": 42}}
        }
        self.assertEqual(self._admit(self._box(epoch=42), match_keys)["reason_codes"], [])
        self.assertEqual(
            self._admit(self._box(epoch=43), match_keys)["reason_codes"], ["epoch_mismatch"]
        )

    def test_supplied_sign_line_hint_is_never_trusted(self) -> None:
        obj = self._box()
        obj["_sign_line"] = "v1|k-active|deadbeef"
        self.assertEqual(self._admit(obj)["decision"], "allow")


class CliParityTests(unittest.TestCase):
    def _run_cli(self, case: str, tmp: Path):
        report_path = tmp / f"{case}-report.json"
        store_path = tmp / f"{case}-store.json"
        proc = subprocess.run(
            [
                sys.executable, "-m", "sealedbox", "admit",
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

    def test_load_failure_exits_two_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            report_path = tmp / "report.json"
            store_path = tmp / "store.json"
            proc = subprocess.run(
                [
                    sys.executable, "-m", "sealedbox", "admit",
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
            self.assertFalse(store_path.exists())


if __name__ == "__main__":
    unittest.main()
