from aclgrant.lifecycle import MIGRATE_PHASES, SOURCE_AFTER, TARGET_AFTER, require_phase


class Handover:
    def __init__(self, store):
        self.store = store

    def move(self, source_id: str, target_id: str, channel: str) -> dict:
        sessions = self.store.data["sessions"]
        source = sessions[source_id]
        if target_id in sessions:
            raise ValueError("target already exists")
        require_phase(source, MIGRATE_PHASES)
        target = dict(source)
        target["id"] = target_id
        target["channel"] = channel
        target["phase"] = TARGET_AFTER
        target["lineage"] = list(source["lineage"]) + [source_id]
        target["work"] = dict(source["work"])
        target["work"]["payload"] = dict(source["work"]["payload"])
        # Cursor id stays shared, so later appends mutate the source cursor.
        source["phase"] = SOURCE_AFTER
        sessions[target_id] = target
        self.store.append("migrate", source=source_id, target=target_id, channel=channel)
        self.store.save()
        return target
