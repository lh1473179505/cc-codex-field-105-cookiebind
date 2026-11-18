import hashlib
import hmac


def signature(path, digest, role, secret):
    line = "|".join((path, digest, role)).encode()
    return hmac.new(secret.encode(), line, hashlib.sha256).hexdigest()


class Delegations:
    def __init__(self, roles):
        self.roles = dict(roles)

    def check(self, path, digest, role, supplied):
        secret = self.roles.get(role)
        expected = signature(path, digest, role, secret or "")
        if not secret or not hmac.compare_digest(expected, supplied):
            raise ValueError("target delegation mismatch")
