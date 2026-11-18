"""Executable online and failure-path scenarios used by CLI and tests."""
from __future__ import annotations

import types
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


def _permission_outcome(action) -> str:
    try:
        action()
    except PermissionError:
        return "rejected"
    return "admitted"


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

    source_session = store.data["sessions"][SOURCE]
    target_session = store.data["sessions"][TARGET]
    source_work = source_session[WORK_KEY]
    target_work = target_session[WORK_KEY]

    # Cross-phase takeover: in-flight transaction, mutable payload and cursor
    # of source and target must have independent lifetimes (no aliasing).
    target_work["payload"]["mutual"] = False
    takeover = {
        "source_transaction": source_work["tx"],
        "target_transaction": target_work["tx"],
        "source_payload": source_work["payload"],
        "target_payload": target_work["payload"],
        "work_containers_distinct": source_work is not target_work,
        "payloads_distinct": source_work["payload"] is not target_work["payload"],
        "stored_payloads_distinct": (
            store.data["transactions"][OLD_TX]["payload"]
            is not store.data["transactions"][NEW_TX]["payload"]
        ),
        "cross_session_commit": _permission_outcome(
            lambda: service.establish_context(SOURCE, NEW_TX)
        ),
    }

    epoch_before = store.epoch(AUTHORITY)
    service.revoke_realm(AUTHORITY)
    epoch_after = store.epoch(AUTHORITY)
    revocation = {
        "epoch_before": epoch_before,
        "epoch_after": epoch_after,
        "new_work_from_old_session": _permission_outcome(
            lambda: service.stage_context(SOURCE, "spnegox-denied-tx", NEW_PAYLOAD)
        ),
        "in_flight_finish": service.establish_context(SOURCE, OLD_TX)["status"],
    }

    journal_before_audit = len(store.data["journal"])
    before = store.state_path.read_bytes()
    first_report = negotiation_trace(store)
    second_report = negotiation_trace(store)
    diagnostics = {
        "state_bytes": "unchanged" if before == store.state_path.read_bytes() else "changed",
        "journal_events": journal_before_audit,
        "journal_untouched": len(store.data["journal"]) == journal_before_audit,
        "repeatable": first_report == second_report,
        "digest": first_report["digest"],
    }

    recovery_state = Path(work) / "recovered.json"
    recovered = resume_negotiations(store.journal_path, recovery_state)
    offline_report = negotiation_trace(types.SimpleNamespace(data=recovered))
    journal_order = [event["op"] for event in store.data["journal"]]
    replay = {
        "journal_order": journal_order,
        "journal_seq_monotonic": [
            event["seq"] for event in store.data["journal"]
        ] == list(range(1, len(store.data["journal"]) + 1)),
        "phases": {
            key: value["phase"] for key, value in recovered["sessions"].items()
        },
        "transactions": {
            key: value["status"] for key, value in recovered["transactions"].items()
        },
        "digest": offline_report["digest"],
    }
    consistency = {
        "conclusion": "match" if offline_report == first_report else "diverged",
        "online_digest": first_report["digest"],
        "offline_digest": offline_report["digest"],
    }
    regression = {
        "cross_stage_takeover": takeover,
        "authority_revocation": revocation,
        "read_only_diagnostics": diagnostics,
        "recovery_replay": replay,
        "online_offline_consistency": consistency,
    }
    healthy = (
        takeover["source_transaction"] == OLD_TX
        and takeover["target_transaction"] == NEW_TX
        and takeover["work_containers_distinct"]
        and takeover["payloads_distinct"]
        and takeover["stored_payloads_distinct"]
        and takeover["cross_session_commit"] == "rejected"
        and revocation["new_work_from_old_session"] == "rejected"
        and revocation["in_flight_finish"] == "committed"
        and diagnostics["state_bytes"] == "unchanged"
        and diagnostics["journal_untouched"]
        and diagnostics["repeatable"]
        and replay["journal_seq_monotonic"]
        and consistency["conclusion"] == "match"
    )
    return {
        "protocol": 'SPNEGO 机制协商交接',
        "status": "ok" if healthy else "failed",
        "regression": regression,
    }
