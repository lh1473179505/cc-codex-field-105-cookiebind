import json
from .counters import Counters
from .groups import Groups
from .arming import arm, ArmInterrupt
from .recovery import recover
from .monitor import legacy_monitor

def main():
    counters = Counters()
    groups = Groups(counters)
    groups.create("sched", [0, 1])
    try:
        arm(groups, "sched", interrupt=True)
    except ArmInterrupt:
        pass
    groups.cancel("sched")
    recovered = recover(groups)
    view = legacy_monitor(groups)["events"][0]
    print(json.dumps({"recovered": recovered, "event": view, "units": counters.units,
                      "cancelled_group_rearmed": view["running"]}, sort_keys=True))
    return 0 if recovered == ["sched"] and view["running"] else 1
