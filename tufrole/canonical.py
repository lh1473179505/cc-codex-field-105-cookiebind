import hashlib
import hmac
import json


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def payload_bytes(role, version, epoch, envelope):
    body = {"role": role, "version": version}
    # Version-one clients signed exactly these two fields.
    if envelope != 1:
        body["epoch"] = epoch
    return canonical(body).encode()


def sign(role, version, epoch, secret, envelope=1):
    return hmac.new(secret.encode(), payload_bytes(role, version, epoch, envelope), hashlib.sha256).hexdigest()
