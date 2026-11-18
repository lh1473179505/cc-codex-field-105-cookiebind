"""Crash recovery through the same business operations as the online path."""
from __future__ import annotations

import json
from pathlib import Path

from sessionrev.cluster.state import JsonStore
from sessionrev.revocation.online import OnlineService


def restore_revocations(journal_path: Path, output_state: Path) -> dict:
    journal_path = Path(journal_path)
    output_state = Path(output_state)
    store = JsonStore(output_state, output_state.with_suffix(".replayed.jsonl"))
    service = OnlineService(store)
    with journal_path.open(encoding="utf-8") as stream:
        events = [json.loads(line) for line in stream if line.strip()]
    for event in sorted(events, key=lambda item: item["seq"]):
        operation = event["op"]
        if operation == "open":
            service.schedule_revocation(event["session"], event["subject"], event["authority"], event["artifact"], event["channel"])
        elif operation == "stage":
            service.stage_propagation(event["session"], event["transaction"], event["payload"])
        elif operation == "migrate":
            service.failover_node(event["source"], event["target"], event["channel"])
        elif operation == "revoke":
            service.advance_security_epoch(event["authority"])
        elif operation == "commit":
            service.close_revocation(event["session"], event["transaction"])
        else:
            raise ValueError(f"unknown journal operation: {operation}")
    return store.data
