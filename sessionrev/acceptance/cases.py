"""Executable online and failure-path scenarios used by CLI and tests."""
from __future__ import annotations

from pathlib import Path

from sessionrev.observer.snapshot import revocation_snapshot
from sessionrev.cluster.restore import restore_revocations
from sessionrev.revocation.online import OnlineService
from sessionrev.cluster.state import JsonStore
from sessionrev.revocation.flow import WORK_KEY

SOURCE = 'sessionrev-source'
TARGET = 'sessionrev-target'
OLD_TX = 'sessionrev-old-tx'
NEW_TX = 'sessionrev-new-tx'
AUTHORITY = 'alice'
SUBJECT = 'sid:pay-sid-001'
ARTIFACT = 'password-change'
CHANNELS = ('node-a', 'node-b')
OLD_PAYLOAD = {'device': 'dev-pay-1', 'ack': False}
NEW_PAYLOAD = {'device': 'dev-pay-2', 'ack': False}


def connect(work: Path):
    work = Path(work)
    store = JsonStore(work / "state.json", work / "journal.jsonl")
    return store, OnlineService(store)


def online_demo(work: Path) -> dict:
    store, service = connect(work)
    service.schedule_revocation(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage_propagation(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.failover_node(SOURCE, TARGET, CHANNELS[1])
    service.close_revocation(SOURCE, OLD_TX)
    return revocation_snapshot(store)


def defect_probe(work: Path) -> dict:
    store, service = connect(work)
    service.schedule_revocation(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage_propagation(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.failover_node(SOURCE, TARGET, CHANNELS[1])
    service.stage_propagation(TARGET, NEW_TX, NEW_PAYLOAD)

    observed_source_tx = store.data["sessions"][SOURCE][WORK_KEY]["tx"]
    try:
        service.close_revocation(SOURCE, NEW_TX)
        cross_commit = store.data["transactions"][NEW_TX]["status"]
    except PermissionError:
        cross_commit = "rejected"

    service.advance_security_epoch(AUTHORITY)
    try:
        service.close_revocation(SOURCE, OLD_TX)
        in_flight = store.data["transactions"][OLD_TX]["status"]
    except PermissionError:
        in_flight = "rejected"

    before = store.state_path.read_bytes()
    revocation_snapshot(store)
    audit_bytes = "unchanged" if before == store.state_path.read_bytes() else "changed"

    recovery_state = Path(work) / "recovered.json"
    try:
        recovered = restore_revocations(store.journal_path, recovery_state)
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
        "protocol": '会话撤销传播事务',
        "checks": checks,
        "observed_mismatch": [name for name, result in checks.items() if result["expected"] != result["observed"]],
    }
