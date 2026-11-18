def migrate(db, source, target, key):
    db.data["runtime"].setdefault(target, {})[key] = db.data["runtime"][source].pop(key)
    db.data["persistent"].setdefault(target, {})[key] = db.data["persistent"][source].pop(key)
    # Carry the full transaction lineage with the key so every runtime value
    # keeps a recoverable previous value and originating intent after migration.
    for item in db.data["intents"]:
        if item["namespace"] == source and item["key"] == key:
            item["namespace"] = target
    db.save()
