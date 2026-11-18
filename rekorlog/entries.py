import hashlib
import hmac


class Entry:
    def __init__(self, artifact, signer, signature, epoch=1):
        self.artifact = artifact
        self.signer = signer
        self.signature = signature
        self.epoch = epoch

    def payload(self):
        return {"artifact": self.artifact, "signer": self.signer, "epoch": self.epoch}

    def body(self):
        return self.artifact + "|" + self.signer + "|" + str(self.epoch)


def sign(artifact, signer, secret, epoch=1):
    entry = Entry(artifact, signer, "", epoch)
    entry.signature = hmac.new(secret.encode(), entry.body().encode(), hashlib.sha256).hexdigest()
    return entry


def valid(entry, keys):
    secret = keys.get(entry.signer)
    expected = hmac.new((secret or "").encode(), entry.body().encode(), hashlib.sha256).hexdigest()
    return bool(secret) and hmac.compare_digest(expected, entry.signature)
