import hashlib
import hmac


def platform_key(platform):
    return platform["os"] + "/" + platform["architecture"] + "/" + platform.get("variant", "")


def approve(descriptor, secret):
    body = (descriptor["digest"] + "|" + platform_key(descriptor["platform"])).encode()
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


class PlatformVerifier:
    def __init__(self, secret):
        self.secret = secret

    def verify(self, descriptor, signature):
        if not hmac.compare_digest(approve(descriptor, self.secret), signature):
            raise ValueError("platform approval mismatch")
