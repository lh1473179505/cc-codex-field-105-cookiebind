class Access:
    def __init__(self):
        self.epoch = 1
        self.revoked = set()

    def check(self, message):
        return message.epoch >= self.epoch and message.epoch not in self.revoked

    def revoke(self, epoch):
        self.revoked.add(epoch)
        self.epoch = max(self.epoch, epoch + 1)
