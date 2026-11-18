"""Executable online and failure-path scenarios used by CLI and tests."""
from __future__ import annotations

from pathlib import Path

from fidoassert.telemetry.auditor import assertion_audit
from fidoassert.persistence.resume import resume_ceremonies
from fidoassert.verification.engine import OnlineService
from fidoassert.persistence.jsondb import JsonStore
from fidoassert.ceremony.phase import WORK_KEY

SOURCE = 'fidoassert-source'
TARGET = 'fidoassert-target'
OLD_TX = 'fidoassert-old-tx'
NEW_TX = 'fidoassert-new-tx'
AUTHORITY = 'pay.example'
SUBJECT = 'credential:cred-pay-1'
ARTIFACT = 'https://app.pay.example'
CHANNELS = ('platform-key', 'roaming-key')
OLD_PAYLOAD = {'sign_count': 42, 'uv': True}
NEW_PAYLOAD = {'sign_count': 7, 'uv': False}


def connect(work: Path):
    work = Path(work)
    store = JsonStore(work / "state.json", work / "journal.jsonl")
    return store, OnlineService(store)


def online_demo(work: Path) -> dict:
    store, service = connect(work)
    service.open_ceremony(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage_assertion(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.roam_authenticator(SOURCE, TARGET, CHANNELS[1])
    service.accept_assertion(SOURCE, OLD_TX)
    return assertion_audit(store)


def defect_probe(work: Path) -> dict:
    store, service = connect(work)
    service.open_ceremony(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage_assertion(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.roam_authenticator(SOURCE, TARGET, CHANNELS[1])
    service.stage_assertion(TARGET, NEW_TX, NEW_PAYLOAD)

    observed_source_tx = store.data["sessions"][SOURCE][WORK_KEY]["tx"]
    try:
        service.accept_assertion(SOURCE, NEW_TX)
        cross_commit = store.data["transactions"][NEW_TX]["status"]
    except PermissionError:
        cross_commit = "rejected"

    service.revoke_relying_party(AUTHORITY)
    try:
        service.accept_assertion(SOURCE, OLD_TX)
        in_flight = store.data["transactions"][OLD_TX]["status"]
    except PermissionError:
        in_flight = "rejected"

    before = store.state_path.read_bytes()
    assertion_audit(store)
    audit_bytes = "unchanged" if before == store.state_path.read_bytes() else "changed"

    recovery_state = Path(work) / "recovered.json"
    try:
        recovered = resume_ceremonies(store.journal_path, recovery_state)
        recovery = recovered["transactions"][OLD_TX]["status"]
    except (PermissionError, RuntimeError) as error:
        recovery = f"error:{error}"

    checks = {
        "source_work_after_target_stage": {"expected": OLD_TX, "observed": observed_source_tx},
        "cross_session_commit": {"expected": "rejected", "observed": cross_commit},
        "in_flight_after_revoke": {"expected": "committed", "observed": in_flight},
        "audit_bytes": {"expected": "unchanged", "observed": audit_bytes},
        "combined_recovery": {"expected": "committed", "observed": recovery},
    }
    return {
        "protocol": 'FIDO2 断言验证器迁移',
        "checks": checks,
        "observed_mismatch": [name for name, result in checks.items() if result["expected"] != result["observed"]],
    }
