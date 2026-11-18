class BatchAck:
    def __init__(self, storage, remote):
        self.storage = storage
        self.remote = remote

    def delete(self, keys):
        selected = [self.storage.items[k] for k in keys]
        for item in selected:
            item.state = "acked"
        self.remote.delete([i.body for i in selected])
