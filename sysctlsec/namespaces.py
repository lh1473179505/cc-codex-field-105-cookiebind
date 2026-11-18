def migrate(db, source, target, key):
    value = db.data["runtime"][source].pop(key)
    db.data["runtime"][target][key] = value
    value = db.data["persistent"][source].pop(key)
    db.data["persistent"][target][key] = value
    db.save()
