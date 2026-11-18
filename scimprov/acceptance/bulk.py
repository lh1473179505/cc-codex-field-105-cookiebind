"""Executable online and failure-path scenarios used by CLI and tests."""
from __future__ import annotations

from pathlib import Path

from scimprov.inventory.reader import inventory_snapshot
from scimprov.bulk.resume import resume_batches
from scimprov.provision.pipeline import OnlineService
from scimprov.bulk.storage import JsonStore
from scimprov.resources.lifecycle import WORK_KEY

SOURCE = 'scimprov-source'
TARGET = 'scimprov-target'
OLD_TX = 'scimprov-old-tx'
NEW_TX = 'scimprov-new-tx'
AUTHORITY = 'tenant-pay'
SUBJECT = 'external:pay-alice'
ARTIFACT = 'bulk-pay-1'
CHANNELS = ('worker-a', 'worker-b')
OLD_PAYLOAD = {'operation': 'create', 'attributes': {'userName': 'alice'}}
NEW_PAYLOAD = {'operation': 'replace', 'attributes': {'active': 'true'}}


def connect(work: Path):
    work = Path(work)
    store = JsonStore(work / "state.json", work / "journal.jsonl")
    return store, OnlineService(store)


def online_demo(work: Path) -> dict:
    store, service = connect(work)
    service.stage_batch(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage_resource(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.rebalance_worker(SOURCE, TARGET, CHANNELS[1])
    service.apply_resource(SOURCE, OLD_TX)
    return inventory_snapshot(store)


def defect_probe(work: Path) -> dict:
    store, service = connect(work)
    service.stage_batch(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage_resource(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.rebalance_worker(SOURCE, TARGET, CHANNELS[1])
    service.stage_resource(TARGET, NEW_TX, NEW_PAYLOAD)

    observed_source_tx = store.data["sessions"][SOURCE][WORK_KEY]["tx"]
    try:
        service.apply_resource(SOURCE, NEW_TX)
        cross_commit = store.data["transactions"][NEW_TX]["status"]
    except PermissionError:
        cross_commit = "rejected"

    service.revoke_tenant(AUTHORITY)
    try:
        service.apply_resource(SOURCE, OLD_TX)
        in_flight = store.data["transactions"][OLD_TX]["status"]
    except PermissionError:
        in_flight = "rejected"

    before = store.state_path.read_bytes()
    inventory_snapshot(store)
    audit_bytes = "unchanged" if before == store.state_path.read_bytes() else "changed"

    recovery_state = Path(work) / "recovered.json"
    try:
        recovered = resume_batches(store.journal_path, recovery_state)
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
        "protocol": 'SCIM 批量供应批次交接',
        "checks": checks,
        "observed_mismatch": [name for name, result in checks.items() if result["expected"] != result["observed"]],
    }
