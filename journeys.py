"""Executable online and failure-path scenarios used by CLI and tests."""
from __future__ import annotations

from pathlib import Path

from inspection import inspect_requests
from restore import restore_requests
from broker import OnlineService
from storage import JsonStore
from requests import WORK_KEY

SOURCE = 'parbind-source'
TARGET = 'parbind-target'
OLD_TX = 'parbind-old-tx'
NEW_TX = 'parbind-new-tx'
AUTHORITY = 'pay-web'
SUBJECT = 'alice'
ARTIFACT = 'https://app.pay.example/callback'
CHANNELS = ('browser', 'wallet')
OLD_PAYLOAD = {'claims': {'prompt': 'consent'}, 'amount': '42.00'}
NEW_PAYLOAD = {'claims': {'prompt': 'login'}, 'amount': '7.00'}


def connect(work: Path):
    work = Path(work)
    store = JsonStore(work / "state.json", work / "journal.jsonl")
    return store, OnlineService(store)


def online_demo(work: Path) -> dict:
    store, service = connect(work)
    service.register(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.prepare_consent(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.rebind(SOURCE, TARGET, CHANNELS[1])
    service.consume(SOURCE, OLD_TX)
    return inspect_requests(store)


def defect_probe(work: Path) -> dict:
    store, service = connect(work)
    service.register(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.prepare_consent(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.rebind(SOURCE, TARGET, CHANNELS[1])
    service.prepare_consent(TARGET, NEW_TX, NEW_PAYLOAD)

    observed_source_tx = store.data["sessions"][SOURCE][WORK_KEY]["tx"]
    try:
        service.consume(SOURCE, NEW_TX)
        cross_commit = store.data["transactions"][NEW_TX]["status"]
    except PermissionError:
        cross_commit = "rejected"

    service.revoke_client(AUTHORITY)
    try:
        service.consume(SOURCE, OLD_TX)
        in_flight = store.data["transactions"][OLD_TX]["status"]
    except PermissionError:
        in_flight = "rejected"

    before = store.state_path.read_bytes()
    inspect_requests(store)
    audit_bytes = "unchanged" if before == store.state_path.read_bytes() else "changed"

    recovery_state = Path(work) / "recovered.json"
    try:
        recovered = restore_requests(store.journal_path, recovery_state)
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
        "protocol": 'PAR 授权句柄迁移',
        "checks": checks,
        "observed_mismatch": [name for name, result in checks.items() if result["expected"] != result["observed"]],
    }
