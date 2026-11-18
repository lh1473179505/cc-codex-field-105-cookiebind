from pathlib import Path

from passkeyx.recover import replay
from passkeyx.service import Service
from passkeyx.store import JsonStore
from passkeyx.view import diagnose

SOURCE = "passkeyx-source"
TARGET = "passkeyx-target"
OLD_TX = "passkeyx-old"
NEW_TX = "passkeyx-new"
AUTHORITY = "rp-id"
SUBJECT = "user:alice"
ARTIFACT = "webauthn:assertion"
CHANNELS = ("browser", "authenticator")
OLD_PAYLOAD = {"scope": ["read", "write"], "depth": 1, "marks": [1]}
NEW_PAYLOAD = {"scope": ["read"], "depth": 0, "marks": [9]}


def connect(work: Path):
    work = Path(work)
    store = JsonStore(work / "state.json", work / "journal.jsonl")
    return store, Service(store)


def online_demo(work: Path) -> dict:
    store, service = connect(work)
    service.prepare(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.move(SOURCE, TARGET, CHANNELS[1])
    service.commit(SOURCE, OLD_TX)
    return diagnose(store)


def defect_probe(work: Path) -> dict:
    store, service = connect(work)
    service.prepare(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.move(SOURCE, TARGET, CHANNELS[1])
    service.stage(TARGET, NEW_TX, NEW_PAYLOAD)
    observed_tx = store.data["sessions"][SOURCE]["work"]["tx"]
    observed_marks = list(store.data["cursors"][store.data["sessions"][SOURCE]["cursor_id"]])
    try:
        service.commit(SOURCE, NEW_TX)
        cross_commit = store.data["transactions"][NEW_TX]["status"]
    except PermissionError:
        cross_commit = "rejected"
    service.revoke(AUTHORITY)
    try:
        service.commit(SOURCE, OLD_TX)
        in_flight = store.data["transactions"][OLD_TX]["status"]
    except PermissionError:
        in_flight = "rejected"
    before = store.state_path.read_bytes()
    diagnose(store)
    audit_bytes = "unchanged" if before == store.state_path.read_bytes() else "changed"
    try:
        recovered = replay(store.journal_path, Path(work) / "recovered.json")
        recovery = recovered["transactions"][OLD_TX]["status"]
    except (PermissionError, RuntimeError) as error:
        recovery = "error:" + str(error)
    checks = {
        "source_work_after_target_stage": {"expected": OLD_TX, "observed": observed_tx},
        "source_cursor_after_target_stage": {"expected": [1], "observed": observed_marks},
        "cross_session_commit": {"expected": "rejected", "observed": cross_commit},
        "in_flight_after_revoke": {"expected": "committed", "observed": in_flight},
        "audit_bytes": {"expected": "unchanged", "observed": audit_bytes},
        "combined_recovery": {"expected": "committed", "observed": recovery},
    }
    return {
        "protocol": "通行密钥仪式交接",
        "checks": checks,
        "observed_mismatch": [name for name, result in checks.items() if result["expected"] != result["observed"]],
    }
