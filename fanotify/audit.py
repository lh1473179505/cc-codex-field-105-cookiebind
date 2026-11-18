def legacy_audit(broker):
    return {"decisions": list(broker.data["decisions"]),
            "events": [{"id": event_id, "path": event["path"], "state": event["state"]}
                       for event_id, event in broker.data["events"].items()]}
