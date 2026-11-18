"""Cross-stage migration and lineage management."""
from __future__ import annotations

from spnegox.negotiation.machine import (
    MIGRATE_PHASES,
    SOURCE_AFTER_TRANSFER,
    TARGET_AFTER_TRANSFER,
    fork_session,
    require_phase,
)


class Migration:
    def __init__(self, store):
        self.store = store

    def bridge_mechanism(self, source_id: str, target_id: str, channel: str) -> dict:
        sessions = self.store.data["sessions"]
        source = sessions[source_id]
        if target_id in sessions:
            raise ValueError("target already exists")
        require_phase(source, tuple(MIGRATE_PHASES))
        target = fork_session(source, target_id, channel, TARGET_AFTER_TRANSFER)
        source["phase"] = SOURCE_AFTER_TRANSFER
        sessions[target_id] = target
        self.store.append("migrate", source=source_id, target=target_id, channel=channel)
        self.store.save()
        return target
