import hashlib
import hmac


PAYLOAD_ALIASES = {"application/vnd.pay.release": "application/vnd.pay.release+json"}


def pae(payload_type, payload):
    return b"DSSEv1 " + str(len(payload_type)).encode() + b" " + payload_type.encode() + b" " + str(len(payload)).encode() + b" " + payload


def sign(secret, payload_type, payload):
    return hmac.new(secret, pae(payload_type, payload), hashlib.sha256).hexdigest()
