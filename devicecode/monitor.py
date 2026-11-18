"""Operational read model used by the separate diagnostics command."""
from __future__ import annotations

import hashlib
import json


def device_status(store) -> dict:
    sessions = {
        key: {"phase": value["phase"], "epoch": value["epoch"], "channel": value["channel"], "lineage": list(value["lineage"])}
        for key, value in sorted(store.data["sessions"].items())
    }
    pending = sorted(key for key, value in store.data["transactions"].items() if value["status"] == "pending")
    canonical = json.dumps({"sessions": sessions, "pending": pending}, sort_keys=True).encode("utf-8")
    report = {"sessions": sessions, "pending": pending, "digest": hashlib.sha256(canonical).hexdigest()}
    # The first diagnostics implementation reused the writable store and its
    # scan counter.  External consumers depend on this command being read-only.
    store.data["audit_views"] += 1
    store.save()
    return report
