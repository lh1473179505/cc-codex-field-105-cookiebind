"""Crash recovery through the same business operations as the online path."""
from __future__ import annotations

import json
from pathlib import Path

from tokenxchg.infra.repository import JsonStore
from tokenxchg.exchange.online import OnlineService


def recover_exchange(journal_path: Path, output_state: Path) -> dict:
    journal_path = Path(journal_path)
    output_state = Path(output_state)
    store = JsonStore(output_state, output_state.with_suffix(".replayed.jsonl"))
    service = OnlineService(store)
    with journal_path.open(encoding="utf-8") as stream:
        events = [json.loads(line) for line in stream if line.strip()]
    for event in sorted(events, key=lambda item: item["seq"]):
        operation = event["op"]
        if operation == "open":
            service.prepare_exchange(event["session"], event["subject"], event["authority"], event["artifact"], event["channel"])
        elif operation == "stage":
            service.stage_delegation(event["session"], event["transaction"], event["payload"])
        elif operation == "migrate":
            service.handover_actor(event["source"], event["target"], event["channel"])
        elif operation == "revoke":
            service.revoke_audience(event["authority"])
        elif operation == "commit":
            service.issue_token(event["session"], event["transaction"])
        else:
            raise ValueError(f"unknown journal operation: {operation}")
    return store.data
