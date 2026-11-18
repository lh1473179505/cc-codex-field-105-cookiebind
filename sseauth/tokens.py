class Tokens:
    def __init__(self):
        self.current_epoch = 1
        self.revoked = set()

    def issue(self, epoch):
        return {"epoch": epoch}

    def revoke(self, epoch):
        self.revoked.add(epoch)
        self.current_epoch = max(self.current_epoch, epoch + 1)

    def valid(self, token):
        return token["epoch"] not in self.revoked
