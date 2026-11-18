import json
import tempfile
from .vault import Vault
from .capture import start, finish, SealFailure
from .cleaner import recover
from .revoke import revoke_owner
from .usage import legacy_usage


def _check(view):
    reserved_total = sum(view["reservations"].values())
    return {
        "used_bytes": view["used_bytes"],
        "reservations": view["reservations"],
        "states": view["states"],
        "conserved": (view["used_bytes"] == reserved_total
                      and view["used_bytes"] >= 0),
    }


def main():
    report = {"stages": [], "expectations": []}

    def snapshot(name, vault):
        entry = {"stage": name, **_check(legacy_usage(vault))}
        report["stages"].append(entry)
        return entry

    with tempfile.TemporaryDirectory() as tmp:
        vault = Vault(tmp)

        start(vault, "core-7", 256, "pay-api")
        snapshot("reserved", vault)

        try:
            finish(vault, "core-7", fail=True)
        except SealFailure:
            report["expectations"].append("seal_failure_raised")
        failed = snapshot("after_failed_seal", vault)
        report["expectations"].append(
            "failed_seal_released_once" if failed["used_bytes"] == 0
            else "FAILED_failed_seal_release")

        first = recover(vault)
        second = recover(vault)
        snapshot("after_two_recoveries", vault)
        report["expectations"].append(
            "recover_reentrant" if first == ["core-7"] and second == []
            else "FAILED_recover_reentry")

        # A restart reopens the same directory and resumes the persisted ledger.
        restarted = Vault(tmp)
        third = recover(restarted)
        after_restart = snapshot("after_restart_recovery", restarted)
        report["expectations"].append(
            "restart_state_resumed" if third == [] and after_restart["used_bytes"] == 0
            else "FAILED_restart_resume")

        # The released quota is real: oversized dumps stay rejected, while a
        # request that fits the original limit is accepted.
        try:
            start(restarted, "core-8", 1024, "pay-api")
            report["expectations"].append("FAILED_oversize_accepted")
        except MemoryError:
            report["expectations"].append("oversize_rejected")

        start(restarted, "core-8", 512, "pay-api")
        try:
            start(restarted, "core-9", 512, "pay-api")
            report["expectations"].append("FAILED_boundary_accepted")
        except MemoryError:
            report["expectations"].append("quota_boundary_enforced")
        finish(restarted, "core-8")
        snapshot("after_new_request", restarted)

        # Revocation blocks new dumps, but cannot strand a reserved capture.
        start(restarted, "core-10", 128, "pay-api")
        revoke_owner(restarted, "pay-api")
        try:
            start(restarted, "core-11", 64, "pay-api")
            report["expectations"].append("FAILED_revoked_owner_accepted")
        except PermissionError:
            report["expectations"].append("revoked_owner_blocked")
        try:
            finish(restarted, "core-10", fail=True)
        except SealFailure:
            pass
        recover(restarted)
        final = snapshot("revoked_capture_cleaned", restarted)
        report["expectations"].append(
            "reserved_capture_cleaned_after_revoke" if final["used_bytes"] == 0
            else "FAILED_revoke_cleanup")

        report["ledger_conserved"] = all(stage["conserved"]
                                         for stage in report["stages"])
        report["ok"] = (
            report["ledger_conserved"]
            and all(not item.startswith("FAILED")
                    for item in report["expectations"]))
        print(json.dumps(report, sort_keys=True))
        return 0 if report["ok"] else 1
