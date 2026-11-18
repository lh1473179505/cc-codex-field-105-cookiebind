import json
from pathlib import Path

from caplease.service import Service
from caplease.store import JsonStore


def replay(journal_path: Path, output_state: Path) -> dict:
    journal_path = Path(journal_path)
    output_state = Path(output_state)
    store = JsonStore(output_state, output_state.with_suffix(".replayed.jsonl"))
    service = Service(store)
    with journal_path.open(encoding="utf-8") as stream:
        events = [json.loads(line) for line in stream if line.strip()]
    for event in sorted(events, key=lambda item: item["seq"]):
        operation = event["op"]
        if operation == "open":
            service.prepare(event["session"], event["subject"], event["authority"], event["artifact"], event["channel"])
        elif operation == "stage":
            service.stage(event["session"], event["transaction"], event["payload"])
        elif operation == "migrate":
            service.move(event["source"], event["target"], event["channel"])
        elif operation == "revoke":
            service.revoke(event["authority"])
        elif operation == "commit":
            service.commit(event["session"], event["transaction"])
        else:
            raise ValueError("unknown journal operation: " + operation)
    return store.data
