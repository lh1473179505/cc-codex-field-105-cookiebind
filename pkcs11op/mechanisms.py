import hashlib
import hmac


def operate(secret, mechanism, usage, payload):
    if (mechanism, usage) not in {("ECDSA_SHA256", "sign"), ("AES_KEY_WRAP", "wrap")}:
        raise ValueError("mechanism and usage disagree")
    return hmac.new(secret, mechanism.encode() + usage.encode() + payload, hashlib.sha256).hexdigest()


def legacy_label(label):
    return {"pay-sign": "pay-sign-01", "ops-wrap": "ops-wrap-01"}.get(label, label)
