"""Executable online and failure-path scenarios used by CLI and tests."""
from __future__ import annotations

from pathlib import Path

from oidclogout.compliance.view import logout_audit
from oidclogout.state.resume import resume_logout
from oidclogout.logout.coordinator import OnlineService
from oidclogout.state.store import JsonStore
from oidclogout.logout.machine import WORK_KEY

SOURCE = 'oidclogout-source'
TARGET = 'oidclogout-target'
OLD_TX = 'oidclogout-old-tx'
NEW_TX = 'oidclogout-new-tx'
AUTHORITY = 'pay-web'
SUBJECT = 'sid:pay-sid-001'
ARTIFACT = 'https://app.pay.example/logged-out'
CHANNELS = ('front-channel', 'back-channel')
OLD_PAYLOAD = {'event': 'frontchannel-logout', 'state': 'state-pay-1'}
NEW_PAYLOAD = {'event': 'backchannel-logout', 'state': 'state-pay-2'}


def connect(work: Path):
    work = Path(work)
    store = JsonStore(work / "state.json", work / "journal.jsonl")
    return store, OnlineService(store)


def online_demo(work: Path) -> dict:
    store, service = connect(work)
    service.announce_logout(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.prepare_delivery(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.switch_backchannel(SOURCE, TARGET, CHANNELS[1])
    service.finish_logout(SOURCE, OLD_TX)
    return logout_audit(store)


def defect_probe(work: Path) -> dict:
    store, service = connect(work)
    service.announce_logout(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.prepare_delivery(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.switch_backchannel(SOURCE, TARGET, CHANNELS[1])
    service.prepare_delivery(TARGET, NEW_TX, NEW_PAYLOAD)

    observed_source_tx = store.data["sessions"][SOURCE][WORK_KEY]["tx"]
    try:
        service.finish_logout(SOURCE, NEW_TX)
        cross_commit = store.data["transactions"][NEW_TX]["status"]
    except PermissionError:
        cross_commit = "rejected"

    service.revoke_relying_party(AUTHORITY)
    try:
        service.finish_logout(SOURCE, OLD_TX)
        in_flight = store.data["transactions"][OLD_TX]["status"]
    except PermissionError:
        in_flight = "rejected"

    before = store.state_path.read_bytes()
    logout_audit(store)
    audit_bytes = "unchanged" if before == store.state_path.read_bytes() else "changed"

    recovery_state = Path(work) / "recovered.json"
    try:
        recovered = resume_logout(store.journal_path, recovery_state)
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
        "protocol": 'OIDC 前后通道登出协同',
        "checks": checks,
        "observed_mismatch": [name for name, result in checks.items() if result["expected"] != result["observed"]],
    }
