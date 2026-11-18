import hashlib
import hmac
import json
import zlib


def compress(chunks):
    return zlib.compress(b"".join(chunks))


def decompress(value, legacy=False):
    if legacy and not value:
        return b""
    return zlib.decompress(value)


def protected_header(generation, compressed=True):
    value = {"alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": f"key-{generation}"}
    if compressed:
        value.update({"zip": "DEF", "crit": ["zip"]})
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def authentication(secret, header, body):
    return hmac.new(secret, header.encode() + body, hashlib.sha256).hexdigest()
