"""Operational read model used by the separate diagnostics command."""
from __future__ import annotations

import hashlib
import json


def logout_audit(store) -> dict:
    sessions = {
        key: {"phase": value["phase"], "epoch": value["epoch"], "channel": value["channel"], "lineage": list(value["lineage"])}
        for key, value in sorted(store.data["sessions"].items())
    }
    pending = sorted(key for key, value in store.data["transactions"].items() if value["status"] == "pending")
    canonical = json.dumps({"sessions": sessions, "pending": pending}, sort_keys=True).encode("utf-8")
    report = {"sessions": sessions, "pending": pending, "digest": hashlib.sha256(canonical).hexdigest()}
    # Diagnostics are read-only: no persistent bytes, journal entries or
    # business counters may change as a side effect of exporting the view.
    return report
