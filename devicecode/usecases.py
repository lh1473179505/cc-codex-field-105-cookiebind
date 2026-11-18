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
EXTRA_TX = 'devicecode-extra-tx'
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

    source_work = store.data["sessions"][SOURCE][WORK_KEY]
    target_work = store.data["sessions"][TARGET][WORK_KEY]
    source_work["payload"]["note"] = "source-local"
    target_work["payload"]["note"] = "target-local"
    migration_work_independent = (
        source_work["tx"] == OLD_TX
        and target_work["tx"] == NEW_TX
        and source_work is not target_work
        and source_work["payload"] is not target_work["payload"]
        and store.data["transactions"][OLD_TX]["payload"] != source_work["payload"]
    )

    try:
        service.redeem_code(SOURCE, NEW_TX)
        cross_session_commit = "committed"
    except PermissionError:
        cross_session_commit = "rejected"

    service.revoke_device_client(AUTHORITY)
    in_flight_after_revoke = service.redeem_code(SOURCE, OLD_TX)["status"]

    stale_session_results = {}
    for stale_session, transaction_id in ((SOURCE, EXTRA_TX), (TARGET, NEW_TX + "-again")):
        try:
            service.stage_verification(stale_session, transaction_id, NEW_PAYLOAD)
            stale_session_results[stale_session] = "accepted"
        except (PermissionError, RuntimeError) as error:
            stale_session_results[stale_session] = f"rejected:{type(error).__name__}"
    stale_sessions_blocked = all(result.startswith("rejected") for result in stale_session_results.values())

    before = store.state_path.read_bytes()
    first_report = device_status(store)
    second_report = device_status(store)
    audit_read_only = (
        before == store.state_path.read_bytes()
        and first_report == second_report
        and set(first_report) == {"sessions", "pending", "digest"}
    )

    recovery_state = Path(work) / "recovered.json"
    rebuild_devices(store.journal_path, recovery_state)
    recovered_store = JsonStore(recovery_state, recovery_state.with_suffix(".replayed.jsonl"))
    online_report = device_status(store)
    offline_report = device_status(recovered_store)
    online_offline_same_conclusion = online_report == offline_report

    invariants = {
        "migration_work_independent": migration_work_independent,
        "cross_session_commit": cross_session_commit,
        "in_flight_after_revoke": in_flight_after_revoke,
        "stale_sessions_blocked": stale_sessions_blocked,
        "audit_read_only": audit_read_only,
        "online_offline_same_conclusion": online_offline_same_conclusion,
    }
    all_hold = (
        migration_work_independent
        and cross_session_commit == "rejected"
        and in_flight_after_revoke == "committed"
        and stale_sessions_blocked
        and audit_read_only
        and online_offline_same_conclusion
    )
    return {
        "protocol": '设备授权码跨端确认',
        "invariants": invariants,
        "online_digest": online_report["digest"],
        "offline_digest": offline_report["digest"],
        "status": "all_invariants_hold" if all_hold else "invariant_violated",
    }
