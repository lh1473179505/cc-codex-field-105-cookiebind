class Stream:
    def __init__(self, stream_id):
        self.stream_id = stream_id
        self.fragments = {}
        self.received = set()
        self.delivered = 0
        self.closed = False

    def add(self, packet):
        token = (packet.offset, packet.data)
        if token in self.received:
            return False
        self.received.add(token)
        self.fragments[packet.offset] = packet
        return True

    def contiguous(self):
        chunks = []
        while self.delivered in self.fragments:
            packet = self.fragments.pop(self.delivered)
            chunks.append(packet.data)
            self.delivered = packet.end
            if packet.final:
                self.closed = True
        return b"".join(chunks)
