"""Crash recovery through the same business operations as the online path."""
from __future__ import annotations

import json
from pathlib import Path

from oidclogout.state.store import JsonStore
from oidclogout.logout.coordinator import OnlineService


def resume_logout(journal_path: Path, output_state: Path) -> dict:
    journal_path = Path(journal_path)
    output_state = Path(output_state)
    store = JsonStore(output_state, output_state.with_suffix(".replayed.jsonl"))
    service = OnlineService(store)
    with journal_path.open(encoding="utf-8") as stream:
        events = [json.loads(line) for line in stream if line.strip()]
    for event in sorted(events, key=lambda item: item["seq"]):
        operation = event["op"]
        if operation == "open":
            service.announce_logout(event["session"], event["subject"], event["authority"], event["artifact"], event["channel"])
        elif operation == "stage":
            service.prepare_delivery(event["session"], event["transaction"], event["payload"])
        elif operation == "migrate":
            service.switch_backchannel(event["source"], event["target"], event["channel"])
        elif operation == "revoke":
            service.revoke_relying_party(event["authority"])
        elif operation == "commit":
            service.finish_logout(event["session"], event["transaction"])
        else:
            raise ValueError(f"unknown journal operation: {operation}")
    return store.data
