from .daemon import lookup

def session_table(sessions):
    rows = []
    for sid, item in sessions.items.items():
        routed = lookup(sessions, item["namespace"], item["pid"])
        rows.append({"session": sid, "namespace": item["namespace"], "pid": item["pid"],
                     "state": item["state"], "routable": routed is item})
    return {"sessions": rows}
