"""Executable online and failure-path scenarios used by CLI and tests."""
from __future__ import annotations

from pathlib import Path

from recoveryx.review.report import recovery_report
from recoveryx.vault.restore import restore_recovery
from recoveryx.reset.service import OnlineService
from recoveryx.vault.state import JsonStore
from recoveryx.reset.flow import WORK_KEY

SOURCE = 'recoveryx-source'
TARGET = 'recoveryx-target'
OLD_TX = 'recoveryx-old-tx'
NEW_TX = 'recoveryx-new-tx'
AUTHORITY = 'user-pay-1'
SUBJECT = 'alice'
ARTIFACT = 'PAY1-ABCD-2345'
CHANNELS = ('web', 'cli')
OLD_PAYLOAD = {'channel_attempt': 1, 'used': False}
NEW_PAYLOAD = {'channel_attempt': 2, 'used': False}


def connect(work: Path):
    work = Path(work)
    store = JsonStore(work / "state.json", work / "journal.jsonl")
    return store, OnlineService(store)


def online_demo(work: Path) -> dict:
    store, service = connect(work)
    service.issue_recovery(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage_attempt(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.relocate_channel(SOURCE, TARGET, CHANNELS[1])
    service.complete_reset(SOURCE, OLD_TX)
    return recovery_report(store)


def defect_probe(work: Path) -> dict:
    store, service = connect(work)
    service.issue_recovery(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage_attempt(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.relocate_channel(SOURCE, TARGET, CHANNELS[1])
    service.stage_attempt(TARGET, NEW_TX, NEW_PAYLOAD)

    observed_source_tx = store.data["sessions"][SOURCE][WORK_KEY]["tx"]
    try:
        service.complete_reset(SOURCE, NEW_TX)
        cross_commit = store.data["transactions"][NEW_TX]["status"]
    except PermissionError:
        cross_commit = "rejected"

    service.revoke_user_epoch(AUTHORITY)
    try:
        service.complete_reset(SOURCE, OLD_TX)
        in_flight = store.data["transactions"][OLD_TX]["status"]
    except PermissionError:
        in_flight = "rejected"

    before = store.state_path.read_bytes()
    recovery_report(store)
    audit_bytes = "unchanged" if before == store.state_path.read_bytes() else "changed"

    recovery_state = Path(work) / "recovered.json"
    try:
        recovered = restore_recovery(store.journal_path, recovery_state)
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
        "protocol": '恢复码渠道迁移与重置',
        "checks": checks,
        "observed_mismatch": [name for name, result in checks.items() if result["expected"] != result["observed"]],
    }
