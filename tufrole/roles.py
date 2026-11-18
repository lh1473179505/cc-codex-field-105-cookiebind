class Role:
    def __init__(self, name, version, epoch, signature, envelope=1):
        self.name = name
        self.version = version
        self.epoch = epoch
        self.signature = signature
        self.envelope = envelope

    def record(self):
        return {
            "name": self.name,
            "version": self.version,
            "epoch": self.epoch,
            "signature": self.signature,
            "envelope": self.envelope,
        }
