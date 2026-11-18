class Peer:
    def __init__(self, fail=()):
        self.fail = set(fail)
        self.payloads = []

    def write(self, stream_id, payload):
        if payload in self.fail:
            raise OSError(payload.decode())
        self.payloads.append((stream_id, payload))
