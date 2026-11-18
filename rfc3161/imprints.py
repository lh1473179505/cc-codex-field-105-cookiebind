import base64
import hashlib
import json


def imprint(payload):
    return hashlib.sha256(payload).hexdigest()


def request_frame(identifier, digest, nonce, legacy=False):
    value = {"id": identifier, "imprint": digest, "nonce": nonce, "certReq": True}
    if not legacy:
        value["policy"] = "1.2.3.4.1"
    return base64.b64encode(json.dumps(value, sort_keys=True).encode()).decode()


def verify_frame(frame, nonce):
    try:
        value = json.loads(base64.b64decode(frame))
    except Exception as exc:
        raise ValueError("malformed timestamp response") from exc
    if value.get("nonce") != nonce or "imprint" not in value:
        raise ValueError("response binding mismatch")
    return value
