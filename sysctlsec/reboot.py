from . import machine

def _rollback_runtime(db, item):
    db.data["runtime"][item["namespace"]][item["key"]] = item["before_runtime"]
    item["status"] = machine.ABORTED

def _rollback_durable(db, item):
    db.data["persistent"][item["namespace"]][item["key"]] = item["before_persistent"]
    db.data["runtime"][item["namespace"]][item["key"]] = item["before_runtime"]
    item["status"] = machine.ABORTED

def _complete_durable(db, item):
    db.data["persistent"][item["namespace"]][item["key"]] = item["value"]
    item["status"] = machine.COMMITTED

def recover(db):
    """Reconcile runtime and persistent state after an interrupted boot.

    Every open intent is resolved under the epoch captured when the intent was
    proposed; recovery never advances ``db.data["epoch"]`` and never requires a
    fresh entry in ``db.data["active"]``.
    """
    recovered = []
    for item in db.data["intents"]:
        if item["status"] not in machine.OPEN_STATES:
            continue
        # Recovery continues the original transaction epoch.
        if item["epoch"] > db.data["epoch"]:
            raise RuntimeError("intent epoch is newer than the recovered epoch")
        if item["status"] == machine.PROPOSED:
            _rollback_durable(db, item)
        elif item["status"] == machine.RUNTIME_WRITTEN:
            _rollback_runtime(db, item)
        else:  # DURABLE_WRITTEN
            _complete_durable(db, item)
        recovered.append(item["token"])
    # Startup verification: any runtime value that still diverges from the
    # durable value has no owning intent and must be rolled back.
    for namespace, values in db.data["runtime"].items():
        durable = db.data["persistent"].get(namespace, {})
        for key, value in list(values.items()):
            if value != durable.get(key):
                values[key] = durable.get(key)
    db.save()
    return recovered

def untracked_runtime_writes(db):
    """Runtime values that diverge from durable storage with no open intent."""
    open_claims = {
        (item["namespace"], item["key"])
        for item in db.data["intents"]
        if item["status"] in machine.OPEN_STATES
    }
    untracked = []
    for namespace, values in db.data["runtime"].items():
        durable = db.data["persistent"].get(namespace, {})
        for key, value in values.items():
            if value != durable.get(key) and (namespace, key) not in open_claims:
                untracked.append({"namespace": namespace, "key": key,
                                  "runtime": value, "persistent": durable.get(key)})
    return untracked
