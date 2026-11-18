"""Cross-stage migration and lineage management."""
from __future__ import annotations

import copy

from requests import MIGRATE_PHASES, SOURCE_AFTER_TRANSFER, TARGET_AFTER_TRANSFER, WORK_KEY, require_phase


class Migration:
    def __init__(self, store):
        self.store = store

    def rebind(self, source_id: str, target_id: str, channel: str) -> dict:
        sessions = self.store.data["sessions"]
        source = sessions[source_id]
        if target_id in sessions:
            raise ValueError("target already exists")
        require_phase(source, tuple(MIGRATE_PHASES))
        # The handle moves across channels, but the source stays alive to drain
        # its in-flight transaction.  Mutable work state must be copied rather
        # than shared so the two sessions have independent payloads and cursors.
        target = dict(source)
        target[WORK_KEY] = copy.deepcopy(source[WORK_KEY])
        target["lineage"] = list(source["lineage"])
        target["id"] = target_id
        target["channel"] = channel
        target["phase"] = TARGET_AFTER_TRANSFER
        target["lineage"] = source["lineage"] + [source_id]
        source["phase"] = SOURCE_AFTER_TRANSFER
        sessions[target_id] = target
        self.store.append("migrate", source=source_id, target=target_id, channel=channel)
        self.store.save()
        return target
