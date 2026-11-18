"""Cross-stage migration and lineage management."""
from __future__ import annotations

from recoveryx.reset.flow import MIGRATE_PHASES, SOURCE_AFTER_TRANSFER, TARGET_AFTER_TRANSFER, WORK_KEY, require_phase


class Migration:
    def __init__(self, store):
        self.store = store

    def relocate_channel(self, source_id: str, target_id: str, channel: str) -> dict:
        sessions = self.store.data["sessions"]
        source = sessions[source_id]
        if target_id in sessions:
            raise ValueError("target already exists")
        require_phase(source, tuple(MIGRATE_PHASES))
        target = dict(source)
        target["id"] = target_id
        target["channel"] = channel
        target["phase"] = TARGET_AFTER_TRANSFER
        target[WORK_KEY] = {"tx": source[WORK_KEY]["tx"], "payload": dict(source[WORK_KEY]["payload"])}
        target["lineage"] = list(source["lineage"]) + [source_id]
        source["phase"] = SOURCE_AFTER_TRANSFER
        sessions[target_id] = target
        self.store.append("migrate", source=source_id, target=target_id, channel=channel)
        self.store.save()
        return target
