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

from jailparam.engine import admit_jail, inspect_jail  # noqa: E402
from jailparam.load import load_json  # noqa: E402

NOW = 1781784000  # 2026-06-18T12:00:00Z

EXPECTED = {
    "ok-pay": ("allow", []),
    "ok-ops": ("allow", []),
    "deny-bad-sig": ("deny", ["bad_signature"]),
    "deny-revoked": ("deny", ["key_revoked"]),
    "deny-name-syntax": ("deny", ["name_syntax"]),
    "deny-name-unknown": ("deny", ["name_unknown"]),
    "deny-jid-range": ("deny", ["jid_range"]),
    "deny-jid-binding": ("deny", ["jid_binding"]),
    "deny-hostname": ("deny", ["hostname"]),
    "deny-ip4-syntax": ("deny", ["ip4_syntax"]),
    "deny-ip4-network": ("deny", ["ip4_network"]),
    "deny-ip4-forbidden": ("deny", ["ip4_forbidden"]),
    "deny-path-binding": ("deny", ["path_binding"]),
    "deny-path-traversal": ("deny", ["path_traversal"]),
    "deny-securelevel": ("deny", ["securelevel"]),
    "deny-replay": ("deny", ["nonce_replay"]),
}


class AdmitFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = load_json(ROOT / "fixtures/keys.json")
        self.policy = load_json(ROOT / "fixtures/policy.json")

    def _admit(self, case: str, obj=None, store=None):
        if obj is None:
            obj = load_json(ROOT / f"fixtures/cases/{case}/jail.json")
        if store is None:
            if case == "deny-replay":
                store = load_json(ROOT / "fixtures/store-used.json")
            else:
                store = {"items": {}}
        return admit_jail(
            copy.deepcopy(obj),
            copy.deepcopy(self.keys),
            copy.deepcopy(self.policy),
            store,
            NOW,
        )

    def test_every_fixture_matches_documented_gate(self) -> None:
        for case, (decision, codes) in EXPECTED.items():
            with self.subTest(case=case):
                report = self._admit(case)
                self.assertEqual(report["decision"], decision)
                self.assertEqual(report["reason_codes"], codes)
                self.assertEqual(report["name"], load_json(
                    ROOT / f"fixtures/cases/{case}/jail.json"
                ).get("name"))

    def test_report_shape(self) -> None:
        report = self._admit("ok-pay")
        self.assertEqual(set(report), {"decision", "reason_codes", "name"})
        self.assertEqual(report["decision"], "allow")
        self.assertEqual(report["reason_codes"], [])

    def test_deny_never_mutates_store_and_allow_records_nonce(self) -> None:
        store = {"items": {}}
        report = self._admit("deny-bad-sig", store=store)
        self.assertEqual(report["decision"], "deny")
        self.assertEqual(store, {"items": {}})

        report = self._admit("ok-pay", store=store)
        self.assertEqual(report["decision"], "allow")
        self.assertIn("n-ok-pay", store["items"])
        self.assertEqual(store["items"]["n-ok-pay"], {"ts": NOW})

        replay = self._admit("ok-pay", store=store)
        self.assertEqual(replay["decision"], "deny")
        self.assertEqual(replay["reason_codes"], ["nonce_replay"])
        self.assertEqual(len(store["items"]), 1)

    def test_jid_is_bound_to_named_jail_not_just_in_range(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-pay/jail.json")
        obj["jid"] = 121  # inside jid_min/jid_max but belongs to opsjail
        report = self._admit("ok-pay", obj=obj)
        self.assertEqual(report["reason_codes"], ["jid_binding"])

    def test_boolean_jid_and_securelevel_are_not_integers(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-pay/jail.json")
        obj["jid"] = True
        self.assertEqual(self._admit("ok-pay", obj=obj)["reason_codes"], ["jid_range"])
        obj = load_json(ROOT / "fixtures/cases/ok-ops/jail.json")
        obj["securelevel"] = False
        self.assertEqual(self._admit("ok-ops", obj=obj)["reason_codes"], ["securelevel"])

    def test_jid_range_boundaries(self) -> None:
        for jid, code in [(0, "jid_range"), (1000000, "jid_range")]:
            obj = load_json(ROOT / "fixtures/cases/ok-pay/jail.json")
            obj["jid"] = jid
            self.assertEqual(self._admit("ok-pay", obj=obj)["reason_codes"], [code])

    def test_ip4_uses_real_address_math_not_string_prefix(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-pay/jail.json")
        obj["ip4"] = "10.120.9.2"  # shares the 10.120. prefix but sits outside /24
        self.assertEqual(self._admit("ok-pay", obj=obj)["reason_codes"], ["ip4_network"])

    def test_ip4_special_addresses_rejected(self) -> None:
        for text in ["0.0.0.0", "255.255.255.255", "127.0.0.1", "224.0.0.5", "169.254.0.1"]:
            obj = load_json(ROOT / "fixtures/cases/ok-pay/jail.json")
            obj["ip4"] = text
            with self.subTest(text=text):
                self.assertEqual(
                    self._admit("ok-pay", obj=obj)["reason_codes"], ["ip4_forbidden"]
                )

    def test_ip4_rejects_prefix_and_malformed_text(self) -> None:
        for text in ["10.120.0.2/24", "10.120.0.999", "not-an-ip"]:
            obj = load_json(ROOT / "fixtures/cases/ok-pay/jail.json")
            obj["ip4"] = text
            with self.subTest(text=text):
                self.assertEqual(
                    self._admit("ok-pay", obj=obj)["reason_codes"], ["ip4_syntax"]
                )

    def test_path_traversal_is_not_normalized_away(self) -> None:
        for text in [
            "/jails/pay/../ops",
            "/jails/pay/../pay",
            "//jails/pay",
            "/jails/pay/./sub",
            "/jails/pay\\x",
            "jails/pay",
        ]:
            obj = load_json(ROOT / "fixtures/cases/ok-pay/jail.json")
            obj["path"] = text
            with self.subTest(text=text):
                self.assertEqual(
                    self._admit("ok-pay", obj=obj)["reason_codes"], ["path_traversal"]
                )

    def test_opsjail_securelevel_one_is_denied(self) -> None:
        report = self._admit("deny-securelevel")
        self.assertEqual(report["reason_codes"], ["securelevel"])

    def test_name_syntax_precedes_unknown_lookup(self) -> None:
        self.assertEqual(
            self._admit("deny-name-syntax")["reason_codes"], ["name_syntax"]
        )
        obj = load_json(ROOT / "fixtures/cases/ok-pay/jail.json")
        obj["name"] = "p" * 33
        self.assertEqual(self._admit("ok-pay", obj=obj)["reason_codes"], ["name_syntax"])

    def test_revoked_key_denies_even_with_valid_hmac(self) -> None:
        self.assertEqual(self._admit("deny-revoked")["reason_codes"], ["key_revoked"])

    def test_iat_window_boundaries(self) -> None:
        import base64
        import hashlib
        import hmac

        secret = bytes.fromhex(self.keys["keys"]["k-active"]["secret"])

        def signed(iat):
            obj = load_json(ROOT / "fixtures/cases/ok-pay/jail.json")
            obj["iat"] = iat
            line = (
                "v1|{kid}|{name}|{jid}|{hostname}|{ip4}|{path}|"
                "{securelevel}|{iat}|{nonce}".format(**obj)
            )
            obj["sig"] = base64.urlsafe_b64encode(
                hmac.new(secret, line.encode(), hashlib.sha256).digest()
            ).rstrip(b"=").decode()
            return obj

        self.assertEqual(self._admit("ok-pay", obj=signed(NOW - 600))["decision"], "allow")
        self.assertEqual(
            self._admit("ok-pay", obj=signed(NOW - 601))["reason_codes"], ["iat_window"]
        )
        self.assertEqual(self._admit("ok-pay", obj=signed(NOW + 60))["decision"], "allow")
        self.assertEqual(
            self._admit("ok-pay", obj=signed(NOW + 61))["reason_codes"], ["iat_window"]
        )

    def test_tampering_any_signed_field_breaks_admission(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-pay/jail.json")
        obj["nonce"] = "tampered-nonce"
        report = self._admit("ok-pay", obj=obj)
        self.assertEqual(report["decision"], "deny")
        self.assertIn("bad_signature", report["reason_codes"])

    def test_inspect_output_unchanged(self) -> None:
        obj = load_json(ROOT / "fixtures/cases/ok-pay/jail.json")
        summary = inspect_jail(obj)
        self.assertEqual(
            set(summary),
            {"kid", "name", "jid", "hostname", "ip4", "path", "securelevel", "nonce"},
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
                sys.executable, "-m", "jailparam", "admit",
                "--jail", str(ROOT / f"fixtures/cases/{case}/jail.json"),
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
                    obj = load_json(ROOT / f"fixtures/cases/{case}/jail.json")
                    if case == "deny-replay":
                        lib_store = load_json(ROOT / "fixtures/store-used.json")
                    else:
                        lib_store = {"items": {}}
                    lib = admit_jail(
                        copy.deepcopy(obj), copy.deepcopy(keys),
                        copy.deepcopy(policy), lib_store, NOW,
                    )
                    rc, cli_report, cli_store = self._run_cli(case, tmp)
                    self.assertEqual(cli_report["decision"], lib["decision"])
                    self.assertEqual(cli_report["reason_codes"], lib["reason_codes"])
                    self.assertEqual(cli_report["decision"], decision)
                    self.assertEqual(cli_report["reason_codes"], codes)
                    if decision == "allow":
                        self.assertEqual(rc, 0)
                        self.assertIn(obj["nonce"], cli_store["items"])
                    else:
                        self.assertEqual(rc, 1)
                        if case == "deny-replay":
                            self.assertEqual(cli_store, load_json(
                                ROOT / "fixtures/store-used.json"
                            ))
                        else:
                            self.assertEqual(cli_store, {"items": {}})


if __name__ == "__main__":
    unittest.main()
