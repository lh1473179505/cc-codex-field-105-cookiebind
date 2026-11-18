"""Executable online and failure-path scenarios used by CLI and tests."""
from __future__ import annotations

from pathlib import Path

from spnegox.diagnostics.trace import negotiation_trace
from spnegox.node.resume import resume_negotiations
from spnegox.negotiation.online import OnlineService
from spnegox.node.logstore import JsonStore
from spnegox.negotiation.machine import WORK_KEY

SOURCE = 'spnegox-source'
TARGET = 'spnegox-target'
OLD_TX = 'spnegox-old-tx'
NEW_TX = 'spnegox-new-tx'
AUTHORITY = 'PAY.EXAMPLE'
SUBJECT = 'HTTP/web.pay.example'
ARTIFACT = '10.40.2.5'
CHANNELS = ('spnego', 'krb5')
OLD_PAYLOAD = {'mech': 'spnego', 'mutual': True}
NEW_PAYLOAD = {'mech': 'krb5', 'mutual': True}


def connect(work: Path):
    work = Path(work)
    store = JsonStore(work / "state.json", work / "journal.jsonl")
    return store, OnlineService(store)


def online_demo(work: Path) -> dict:
    store, service = connect(work)
    service.offer_negotiation(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage_context(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.bridge_mechanism(SOURCE, TARGET, CHANNELS[1])
    service.establish_context(SOURCE, OLD_TX)
    return negotiation_trace(store)


def defect_probe(work: Path) -> dict:
    store, service = connect(work)
    service.offer_negotiation(SOURCE, SUBJECT, AUTHORITY, ARTIFACT, CHANNELS[0])
    service.stage_context(SOURCE, OLD_TX, OLD_PAYLOAD)
    service.bridge_mechanism(SOURCE, TARGET, CHANNELS[1])
    service.stage_context(TARGET, NEW_TX, NEW_PAYLOAD)

    observed_source_tx = store.data["sessions"][SOURCE][WORK_KEY]["tx"]
    try:
        service.establish_context(SOURCE, NEW_TX)
        cross_commit = store.data["transactions"][NEW_TX]["status"]
    except PermissionError:
        cross_commit = "rejected"

    service.revoke_realm(AUTHORITY)
    try:
        service.establish_context(SOURCE, OLD_TX)
        in_flight = store.data["transactions"][OLD_TX]["status"]
    except PermissionError:
        in_flight = "rejected"

    before = store.state_path.read_bytes()
    negotiation_trace(store)
    audit_bytes = "unchanged" if before == store.state_path.read_bytes() else "changed"

    recovery_state = Path(work) / "recovered.json"
    try:
        recovered = resume_negotiations(store.journal_path, recovery_state)
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
        "protocol": 'SPNEGO 机制协商交接',
        "checks": checks,
        "observed_mismatch": [name for name, result in checks.items() if result["expected"] != result["observed"]],
    }
