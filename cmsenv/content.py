import hashlib
import hmac


def content_key(identifier, content):
    return hmac.new(identifier.encode(), content, hashlib.sha256).digest()


def wrap(cek, recipient_secret, recipient, generation):
    return hmac.new(recipient_secret, cek + f":{recipient}:{generation}".encode(), hashlib.sha256).hexdigest()


def unwrap(cek, recipient_secret, recipient, generation, value):
    return hmac.compare_digest(wrap(cek, recipient_secret, recipient, generation), value)
