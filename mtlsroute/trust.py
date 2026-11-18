class PeerTrust:
    def __init__(self):
        self.epoch = 1
        self.revoked = set()
        self.allowed = {"edge-a", "edge-b"}

    def admit(self, frame):
        return (
            frame.peer in self.allowed
            and frame.epoch >= self.epoch
            and frame.epoch not in self.revoked
        )

    def rotate(self, peer, new_epoch):
        self.revoked.add(self.epoch)
        self.epoch = max(self.epoch, new_epoch)
        if peer not in self.allowed:
            self.allowed.add(peer)
