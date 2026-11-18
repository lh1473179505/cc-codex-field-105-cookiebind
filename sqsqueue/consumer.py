def inspect(queue):
    return {"states": {k: i.state for k, i in sorted(queue.storage.items.items())},
            "remote": list(queue.remote.deleted)}
