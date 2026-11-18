"""Executable online and failure-path scenarios used by CLI and tests."""
from __future__ import annotations

from pathlib import Path

from cibareq.ops.report import authentication_report
from cibareq.ops.replay import replay_authentication
from cibareq.services.poll import OnlineService
from cibareq.data.journal import JsonStore
from cibareq.domain.states import WORK_KEY

SOURCE = 'cibareq-source'
TARGET = 'cibareq-target'
OLD_TX = 'cibareq-old-tx'
NEW_TX = 'cibareq-new-tx'
AUTHORITY = 'ciba-pay'
SUBJECT = 'user:alice'
ARTIFACT = 'PAY-42'
CHANNELS = ('mobile-poll', 'desktop-poll')
OLD_PAYLOAD = {'interval': 5, 'decision': 'approve'}
NEW_PAYLOAD = {'interval': 10, 'decision': 'deny'}


def connect(work: Path):
    work = Path(work)
    store = JsonStore(work / "state.json", work / "journal.jsonl")
    return store, OnlineService(store)


def online_demo(work: Path) -> dict:
    store, service = connect(work)
    service.start_auth(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.queue_decision(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.move_poll(SOURCE, TARGET, CHANNELS[1])
    service.redeem_auth(SOURCE, OLD_TX)
    return authentication_report(store)


def defect_probe(work: Path) -> dict:
    store, service = connect(work)
    service.start_auth(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.queue_decision(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.move_poll(SOURCE, TARGET, CHANNELS[1])
    service.queue_decision(TARGET, NEW_TX, NEW_PAYLOAD)

    observed_source_tx = store.data["sessions"][SOURCE][WORK_KEY]["tx"]
    try:
        service.redeem_auth(SOURCE, NEW_TX)
        cross_commit = store.data["transactions"][NEW_TX]["status"]
    except PermissionError:
        cross_commit = "rejected"

    service.rotate_client_epoch(AUTHORITY)
    try:
        service.redeem_auth(SOURCE, OLD_TX)
        in_flight = store.data["transactions"][OLD_TX]["status"]
    except PermissionError:
        in_flight = "rejected"

    before = store.state_path.read_bytes()
    authentication_report(store)
    audit_bytes = "unchanged" if before == store.state_path.read_bytes() else "changed"

    recovery_state = Path(work) / "recovered.json"
    try:
        recovered = replay_authentication(store.journal_path, recovery_state)
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
        "protocol": 'CIBA 后端认证轮询接管',
        "checks": checks,
        "observed_mismatch": [name for name, result in checks.items() if result["expected"] != result["observed"]],
    }
