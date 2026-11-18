import hashlib
import hmac


class Signer:
    def __init__(self, secret="store-secret"):
        self.secret = secret

    def signature(self, name, generation):
        return hmac.new(self.secret.encode(), (name + "|" + str(generation)).encode(), hashlib.sha256).hexdigest()

    def valid(self, name, generation, supplied):
        return hmac.compare_digest(self.signature(name, generation), supplied)
