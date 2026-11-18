"""Cross-stage migration and lineage management."""
from __future__ import annotations

from copy import deepcopy

from scimprov.resources.lifecycle import MIGRATE_PHASES, SOURCE_AFTER_TRANSFER, TARGET_AFTER_TRANSFER, require_phase


class Migration:
    def __init__(self, store):
        self.store = store

    def rebalance_worker(self, source_id: str, target_id: str, channel: str) -> dict:
        sessions = self.store.data["sessions"]
        source = sessions[source_id]
        if target_id in sessions:
            raise ValueError("target already exists")
        require_phase(source, tuple(MIGRATE_PHASES))
        # Handover gives the target an independent work area: the in-flight
        # transaction cursor, mutable payload and lineage must not alias the
        # source session, otherwise later staging on either side overwrites
        # the other worker's change set.
        target = deepcopy(source)
        target["id"] = target_id
        target["channel"] = channel
        target["phase"] = TARGET_AFTER_TRANSFER
        target["lineage"] = list(source["lineage"]) + [source_id]
        source["phase"] = SOURCE_AFTER_TRANSFER
        sessions[target_id] = target
        self.store.append("migrate", source=source_id, target=target_id, channel=channel)
        self.store.save()
        return target
