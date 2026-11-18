"""Executable online and failure-path scenarios used by CLI and tests."""
from __future__ import annotations

from pathlib import Path

from tokenxchg.viewer.readonly import exchange_view
from tokenxchg.infra.recover import recover_exchange
from tokenxchg.exchange.online import OnlineService
from tokenxchg.infra.repository import JsonStore
from tokenxchg.exchange.lifecycle import WORK_KEY

SOURCE = 'tokenxchg-source'
TARGET = 'tokenxchg-target'
OLD_TX = 'tokenxchg-old-tx'
NEW_TX = 'tokenxchg-new-tx'
AUTHORITY = 'pay-api'
SUBJECT = 'service:payments'
ARTIFACT = 'urn:ietf:params:oauth:token-type:jwt'
CHANNELS = ('subject-agent', 'actor-agent')
OLD_PAYLOAD = {'scope': ['read', 'write'], 'depth': 1}
NEW_PAYLOAD = {'scope': ['read'], 'depth': 0}


def connect(work: Path):
    work = Path(work)
    store = JsonStore(work / "state.json", work / "journal.jsonl")
    return store, OnlineService(store)


def online_demo(work: Path) -> dict:
    store, service = connect(work)
    service.prepare_exchange(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage_delegation(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.handover_actor(SOURCE, TARGET, CHANNELS[1])
    service.issue_token(SOURCE, OLD_TX)
    return exchange_view(store)


def defect_probe(work: Path) -> dict:
    store, service = connect(work)
    service.prepare_exchange(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage_delegation(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.handover_actor(SOURCE, TARGET, CHANNELS[1])
    service.stage_delegation(TARGET, NEW_TX, NEW_PAYLOAD)

    observed_source_tx = store.data["sessions"][SOURCE][WORK_KEY]["tx"]
    try:
        service.issue_token(SOURCE, NEW_TX)
        cross_commit = store.data["transactions"][NEW_TX]["status"]
    except PermissionError:
        cross_commit = "rejected"

    service.revoke_audience(AUTHORITY)
    try:
        service.issue_token(SOURCE, OLD_TX)
        in_flight = store.data["transactions"][OLD_TX]["status"]
    except PermissionError:
        in_flight = "rejected"

    before = store.state_path.read_bytes()
    exchange_view(store)
    audit_bytes = "unchanged" if before == store.state_path.read_bytes() else "changed"

    recovery_state = Path(work) / "recovered.json"
    try:
        recovered = recover_exchange(store.journal_path, recovery_state)
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
        "protocol": 'OAuth 令牌交换委派交接',
        "checks": checks,
        "observed_mismatch": [name for name, result in checks.items() if result["expected"] != result["observed"]],
    }
