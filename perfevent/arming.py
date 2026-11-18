from . import group_state as states

class ArmInterrupt(RuntimeError):
    pass

def arm(groups, name, fail_cpu=None, interrupt=False):
    item = groups.items[name]
    item["state"] = states.ARMING
    intent = {"group": name, "state": states.ARMING, "epoch": item["epoch"],
              "cgroup": item["cgroup"]}
    groups.intents.append(intent)
    try:
        for cpu in item["requested"]:
            if fail_cpu == cpu:
                raise OSError("PMU busy")
            groups.counters.acquire(cpu)
            item["cpus"].append(cpu)
            if interrupt:
                raise ArmInterrupt("worker stopped")
        item["state"] = states.ARMED
        intent["state"] = states.ARMED
        return item
    except (OSError, ArmInterrupt):
        if interrupt:
            raise
        groups.cancel(name)
        intent["state"] = states.CANCELLED
        return item
