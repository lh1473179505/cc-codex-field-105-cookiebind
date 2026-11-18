import hashlib
import hmac


def derive(secret, info, length=32, legacy=False):
    """RFC 5869 HKDF-SHA256 with the historical v0 empty-salt convention."""
    salt = b"" if legacy else bytes([0]) * hashlib.sha256().digest_size
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info.encode() + bytes([counter]), hashlib.sha256).digest()
        output += previous
        counter += 1
    return output[:length]
