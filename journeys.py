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
RENEWED_TX = 'parbind-renewed-tx'
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


def _require(condition: bool, label: str) -> None:
    if not condition:
        raise AssertionError(f"{label} violated")


def _expect_rejected(action, label: str) -> str:
    try:
        action()
    except PermissionError:
        return "rejected"
    raise AssertionError(f"{label} was not rejected")


def defect_probe(work: Path) -> dict:
    store, service = connect(work)
    service.register(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.prepare_consent(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.rebind(SOURCE, TARGET, CHANNELS[1])
    service.prepare_consent(TARGET, NEW_TX, NEW_PAYLOAD)

    source_work = store.data["sessions"][SOURCE][WORK_KEY]
    target_work = store.data["sessions"][TARGET][WORK_KEY]
    _require(source_work["tx"] == OLD_TX, "source cursor after target stage")
    _require(target_work["tx"] == NEW_TX, "target cursor after target stage")
    _require(source_work is not target_work, "migration work container aliasing")
    _require(source_work["payload"] is not target_work["payload"], "migration payload aliasing")
    target_work["payload"]["claims"]["prompt"] = "tampered"
    _require(store.data["sessions"][SOURCE][WORK_KEY]["payload"]["claims"]["prompt"] == "consent", "payload isolation")

    cross_commit = _expect_rejected(lambda: service.consume(SOURCE, NEW_TX), "cross-session commit")
    _require(store.data["transactions"][NEW_TX]["status"] == "pending", "cross-session commit side effect")

    service.revoke_client(AUTHORITY)
    renewed = _expect_rejected(lambda: service.prepare_consent(SOURCE, RENEWED_TX, NEW_PAYLOAD), "new transaction from stale epoch")
    _require(RENEWED_TX not in store.data["transactions"], "stale epoch transaction side effect")
    in_flight = service.consume(SOURCE, OLD_TX)["status"]
    _require(in_flight == "committed", "in-flight finish after revocation")

    before = store.state_path.read_bytes()
    first_report = inspect_requests(store)
    second_report = inspect_requests(store)
    _require(first_report == second_report, "repeatable diagnostics")
    audit_bytes = "unchanged" if before == store.state_path.read_bytes() else "changed"
    _require(audit_bytes == "unchanged", "read-only diagnostics")

    recovery_state = Path(work) / "recovered.json"
    recovered = restore_requests(store.journal_path, recovery_state)
    _require(
        {key: value["phase"] for key, value in store.data["sessions"].items()}
        == {key: value["phase"] for key, value in recovered["sessions"].items()},
        "recovered session phases",
    )
    _require(
        {key: value["status"] for key, value in store.data["transactions"].items()}
        == {key: value["status"] for key, value in recovered["transactions"].items()},
        "recovered transaction statuses",
    )
    _require(
        {key: value["epoch"] for key, value in store.data["sessions"].items()}
        == {key: value["epoch"] for key, value in recovered["sessions"].items()},
        "recovered permission epochs",
    )
    recovered_store = JsonStore(recovery_state, recovery_state.with_suffix(".replayed.jsonl"))
    offline_report = inspect_requests(recovered_store)
    _require(offline_report == first_report, "online/offline diagnostic equivalence")

    checks = {
        "source_cursor_pinned": source_work["tx"],
        "target_cursor_independent": target_work["tx"],
        "work_state_not_aliased": not (source_work is target_work),
        "cross_session_commit": cross_commit,
        "stale_epoch_new_transaction": renewed,
        "in_flight_after_revoke": in_flight,
        "audit_bytes": audit_bytes,
        "audit_repeatable": first_report == second_report,
        "combined_recovery": recovered["transactions"][OLD_TX]["status"],
    }
    return {
        "protocol": 'PAR 授权句柄迁移',
        "checks": checks,
        "online_digest": first_report["digest"],
        "offline_digest": offline_report["digest"],
        "status": "ok",
    }
