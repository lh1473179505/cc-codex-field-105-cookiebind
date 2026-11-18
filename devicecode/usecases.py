"""Executable online and failure-path scenarios used by CLI and tests."""
from __future__ import annotations

from pathlib import Path

from devicecode.monitor import device_status
from devicecode.rebuild import rebuild_devices
from devicecode.authorization import OnlineService
from devicecode.db import JsonStore
from devicecode.model import WORK_KEY

SOURCE = 'devicecode-source'
TARGET = 'devicecode-target'
OLD_TX = 'devicecode-old-tx'
NEW_TX = 'devicecode-new-tx'
AUTHORITY = 'pay-tv'
SUBJECT = 'device:living-room'
ARTIFACT = 'PAYK-8F2Q'
CHANNELS = ('television', 'companion-app')
OLD_PAYLOAD = {'attempt': 1, 'user_code': 'PAYK-8F2Q'}
NEW_PAYLOAD = {'attempt': 2, 'user_code': 'PAYK-9Z3Q'}


def connect(work: Path):
    work = Path(work)
    store = JsonStore(work / "state.json", work / "journal.jsonl")
    return store, OnlineService(store)


def online_demo(work: Path) -> dict:
    store, service = connect(work)
    service.open_device(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage_verification(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.companion_takeover(SOURCE, TARGET, CHANNELS[1])
    service.redeem_code(SOURCE, OLD_TX)
    return device_status(store)


def defect_probe(work: Path) -> dict:
    store, service = connect(work)
    service.open_device(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage_verification(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.companion_takeover(SOURCE, TARGET, CHANNELS[1])
    service.stage_verification(TARGET, NEW_TX, NEW_PAYLOAD)

    observed_source_tx = store.data["sessions"][SOURCE][WORK_KEY]["tx"]
    try:
        service.redeem_code(SOURCE, NEW_TX)
        cross_commit = store.data["transactions"][NEW_TX]["status"]
    except PermissionError:
        cross_commit = "rejected"

    service.revoke_device_client(AUTHORITY)
    try:
        service.redeem_code(SOURCE, OLD_TX)
        in_flight = store.data["transactions"][OLD_TX]["status"]
    except PermissionError:
        in_flight = "rejected"

    before = store.state_path.read_bytes()
    device_status(store)
    audit_bytes = "unchanged" if before == store.state_path.read_bytes() else "changed"

    recovery_state = Path(work) / "recovered.json"
    try:
        recovered = rebuild_devices(store.journal_path, recovery_state)
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
        "protocol": '设备授权码跨端确认',
        "checks": checks,
        "observed_mismatch": [name for name, result in checks.items() if result["expected"] != result["observed"]],
    }
