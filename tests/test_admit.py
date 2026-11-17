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

from uefidb.engine import admit_update, inspect_update  # noqa: E402
from uefidb.load import load_json  # noqa: E402

NOW = 1781784000  # 2026-06-18T12:00:00Z

EXPECTED = {
    "ok-db-add": ("allow", []),
    "ok-dbx-remove": ("allow", []),
    "deny-bad-sig": ("deny", ["bad_signature"]),
    "deny-revoked": ("deny", ["key_revoked"]),
    "deny-db": ("deny", ["db"]),
    "deny-owner-syntax": ("deny", ["owner_syntax"]),
    "deny-owner-forbidden": ("deny", ["owner_forbidden"]),
    "deny-owner-binding": ("deny", ["owner_binding"]),
    "deny-digest-length": ("deny", ["digest_length"]),
    "deny-digest-syntax": ("deny", ["digest_syntax"]),
    "deny-digest-zero": ("deny", ["digest_zero"]),
    "deny-action": ("deny", ["action"]),
    "deny-append-value": ("deny", ["append_value"]),
    "deny-append-binding": ("deny", ["append_binding"]),
    "deny-auth-method": ("deny", ["auth_method"]),
    "deny-auth-action": ("deny", ["auth_action"]),
    "deny-replay": ("deny", ["nonce_replay"]),
}


def sign(obj: dict, secret_hex: str) -> dict:
    line = "|".join([
        "v1", str(obj["kid"]), str(obj["db"]), str(obj["owner_guid"]),
        str(obj["cert_digest"]), str(obj["action"]), str(obj["append"]),
        str(obj["auth"]), str(obj["iat"]), str(obj["nonce"]),
    ])
    obj["sig"] = base64.urlsafe_b64encode(
        hmac.new(bytes.fromhex(secret_hex), line.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return obj


class AdmitFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = load_json(ROOT / "fixtures/keys.json")
        self.policy = load_json(ROOT / "fixtures/policy.json")

    def _admit(self, case: str, obj=None, store=None, policy=None):
        if obj is None:
            obj = load_json(ROOT / f"fixtures/cases/{case}/update.json")
        if store is None:
            if case == "deny-replay":
                store = load_json(ROOT / "fixtures/store-used.json")
            else:
                store = {"items": {}}
        return admit_update(
            copy.deepcopy(obj),
            copy.deepcopy(self.keys),
            copy.deepcopy(policy if policy is not None else self.policy),
            store,
            NOW,
        )

    def test_every_fixture_matches_documented_gate(self) -> None:
        for case, (decision, codes) in EXPECTED.items():
            with self.subTest(case=case):
                report = self._admit(case)
                self.assertEqual(report["decision"], decision)
                self.assertEqual(report["reason_codes"], codes)
                self.assertEqual(report["db"], load_json(
                    ROOT / f"fixtures/cases/{case}/update.json"
                ).get("db"))

    def test_report_shape(self) -> None:
        report = self._admit("ok-db-add")
        self.assertEqual(set(report), {"decision", "reason_codes", "db"})
        self.assertEqual(report["decision"], "allow")
        self.assertEqual(report["reason_codes"], [])

    def test_deny_never_mutates_store_and_allow_records_nonce(self) -> None:
        store = {"items": {}}
        report = self._admit("deny-bad-sig", store=store)
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(store, {"items": {}})

        report = self._admit("ok-db-add", store=store)
        self.assertEqual(report["decision"], "allow")
        self.assertIn("n-ok-db-add", store["items"])
        self.assertEqual(store["items"]["n-ok-db-add"], {"ts": NOW})

        replay = self._admit("ok-db-add", store=store)
        self.assertEqual(replay["decision"], "deny")
        self.assertEqual(replay["reason_codes"], ["nonce_replay"])
        self.assertEqual(len(store["items"]), 1)

    def test_owner_guid_is_bound_to_the_selected_db(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-dbx-remove/update.json")
        obj["owner_guid"] = self.policy["dbs"]["db"]["owner_guid"]
        report = self._admit("ok-dbx-remove", obj=sign(obj, self.keys["keys"]["k-active"]["secret"]))
        self.assertEqual(report["reason_codes"], ["owner_binding"])

    def test_owner_guid_must_be_canonical_lowercase_and_nonzero(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-db-add/update.json")
        obj["owner_guid"] = "123E4567-E89B-42D3-A456-426614174000"
        self.assertEqual(self._admit("ok-db-add", obj=obj)["reason_codes"], ["owner_syntax"])
        obj["owner_guid"] = "00000000-0000-0000-0000-000000000000"
        self.assertEqual(self._admit("ok-db-add", obj=obj)["reason_codes"], ["owner_forbidden"])

    def test_digest_checks_length_lowercase_hex_and_zero(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-db-add/update.json")
        secret = self.keys["keys"]["k-active"]["secret"]
        variants = [
            ("ef" * 63, "digest_length"),
            ("EF" * 32, "digest_syntax"),
            ("00" * 32, "digest_zero"),
        ]
        for digest, code in variants:
            with self.subTest(digest=digest):
                candidate = dict(obj, cert_digest=digest, nonce=f"n-{code}")
                self.assertEqual(
                    self._admit("ok-db-add", obj=sign(candidate, secret))["reason_codes"],
                    [code],
                )

    def test_zero_digest_flows_when_policy_allows_it(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["forbid_zero_digest"] = False
        obj = load_json(ROOT / "fixtures/cases/ok-db-add/update.json")
        obj["cert_digest"] = "0" * 64
        obj["nonce"] = "n-zero-digest-allowed"
        report = self._admit(
            "ok-db-add",
            obj=sign(obj, self.keys["keys"]["k-active"]["secret"]),
            policy=policy,
        )
        self.assertEqual(report["decision"], "allow")

    def test_append_zero_add_accepted_when_policy_binds_it(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["dbs"]["db"]["append_by_action"]["add"] = 0
        obj = load_json(ROOT / "fixtures/cases/ok-db-add/update.json")
        obj["append"] = 0
        obj["nonce"] = "n-append-zero"
        report = self._admit(
            "ok-db-add",
            obj=sign(obj, self.keys["keys"]["k-active"]["secret"]),
            policy=policy,
        )
        self.assertEqual(report["decision"], "allow")

    def test_boolean_append_is_not_an_integer(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-db-add/update.json")
        obj["append"] = True
        self.assertEqual(self._admit("ok-db-add", obj=obj)["reason_codes"], ["append_value"])

    def test_dbx_remove_requires_both_auth_layers(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-dbx-remove/update.json")
        secret = self.keys["keys"]["k-active"]["secret"]
        candidate = dict(obj, auth="pkcs7-sha256", nonce="n-auth-action")
        self.assertEqual(
            self._admit("ok-dbx-remove", obj=sign(candidate, secret))["reason_codes"],
            ["auth_action"],
        )
        candidate = dict(obj, auth="pkcs7-sha512", nonce="n-auth-method")
        self.assertEqual(
            self._admit("ok-dbx-remove", obj=sign(candidate, secret))["reason_codes"],
            ["auth_method"],
        )

    def test_iat_window_boundaries(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-db-add/update.json")
        secret = self.keys["keys"]["k-active"]["secret"]
        for delta, expected in [(-600, "allow"), (-601, "iat_window"),
                                (60, "allow"), (61, "iat_window")]:
            with self.subTest(delta=delta):
                candidate = dict(obj, iat=NOW + delta, nonce=f"n-iat-{delta}")
                report = self._admit("ok-db-add", obj=sign(candidate, secret))
                self.assertEqual(
                    report["reason_codes"], [] if expected == "allow" else [expected]
                )

    def test_tampering_any_signed_field_breaks_admission(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-db-add/update.json")
        obj["nonce"] = "tampered-nonce"
        report = self._admit("ok-db-add", obj=obj)
        self.assertEqual(report["decision"], "deny")
        self.assertIn("bad_signature", report["reason_codes"])

    def test_unknown_kid_and_revoked_key(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-db-add/update.json")
        obj["kid"] = "k-missing"
        sign(obj, self.keys["keys"]["k-active"]["secret"])
        self.assertEqual(self._admit("ok-db-add", obj=obj)["reason_codes"], ["unknown_key"])
        self.assertEqual(self._admit("deny-revoked")["reason_codes"], ["key_revoked"])

    def test_inspect_output_unchanged(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-db-add/update.json")
        summary = inspect_update(obj)
        self.assertEqual(
            set(summary),
            {"kid", "db", "owner_guid", "cert_digest", "action", "append", "auth", "nonce"},
        )


class CliParityTests(unittest.TestCase):
    def _run_cli(self, case: str, tmp: Path):
        report_path = tmp / f"{case}-report.json"
        store_path = tmp / f"{case}-store.json"
        if case == "deny-replay":
            store_path.write_text(
                (ROOT / "fixtures/store-used.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        else:
            store_path.write_text(
                (ROOT / "fixtures/store-empty.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
        proc = subprocess.run(
            [
                sys.executable, "-m", "uefidb", "admit",
                "--update", str(ROOT / f"fixtures/cases/{case}/update.json"),
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
                    obj = load_json(ROOT / f"fixtures/cases/{case}/update.json")
                    if case == "deny-replay":
                        lib_store = load_json(ROOT / "fixtures/store-used.json")
                    else:
                        lib_store = {"items": {}}
                    lib = admit_update(
                        copy.deepcopy(obj), copy.deepcopy(keys),
                        copy.deepcopy(policy), lib_store, NOW,
                    )
                    rc, cli_report, cli_store = self._run_cli(case, tmp)
                    self.assertEqual(cli_report, lib)
                    self.assertEqual(rc, 0 if decision == "allow" else 1)
                    self.assertEqual(cli_report["reason_codes"], codes)
                    if decision == "deny":
                        self.assertEqual(
                            cli_store,
                            load_json(ROOT / (
                                "fixtures/store-used.json" if case == "deny-replay"
                                else "fixtures/store-empty.json"
                            )),
                        )


if __name__ == "__main__":
    unittest.main()
