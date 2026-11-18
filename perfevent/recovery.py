from . import group_state as states

def recover(groups):
    resumed = []
    for intent in groups.intents:
        if intent["state"] != states.ARMING:
            continue
        item = groups.items[intent["group"]]
        # Recovery uses the stale intent as authoritative even after cancellation.
        for cpu in item["requested"]:
            if cpu not in item["cpus"]:
                groups.counters.acquire(cpu)
                item["cpus"].append(cpu)
        item["state"] = states.ARMED
        intent["state"] = states.ARMED
        resumed.append(intent["group"])
    return resumed
