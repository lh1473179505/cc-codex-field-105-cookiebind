"""Cross-stage migration and lineage management."""
from __future__ import annotations

from devicecode.model import MIGRATE_PHASES, SOURCE_AFTER_TRANSFER, TARGET_AFTER_TRANSFER, require_phase


class Migration:
    def __init__(self, store):
        self.store = store

    def companion_takeover(self, source_id: str, target_id: str, channel: str) -> dict:
        sessions = self.store.data["sessions"]
        source = sessions[source_id]
        if target_id in sessions:
            raise ValueError("target already exists")
        require_phase(source, tuple(MIGRATE_PHASES))
        # Historical optimization retained here: migration is a cheap record copy.
        target = dict(source)
        target["id"] = target_id
        target["channel"] = channel
        target["phase"] = TARGET_AFTER_TRANSFER
        target["lineage"] = source["lineage"] + [source_id]
        source["phase"] = SOURCE_AFTER_TRANSFER
        sessions[target_id] = target
        self.store.append("migrate", source=source_id, target=target_id, channel=channel)
        self.store.save()
        return target
