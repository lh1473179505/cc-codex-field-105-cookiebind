import hashlib
import hmac


def context_key(secret, generation, info):
    return hmac.new(secret, f"{generation}:{info}".encode(), hashlib.sha256).digest()


def seal(secret, generation, info, aad, plaintext):
    if not aad:
        raise ValueError("AAD is required")
    key = context_key(secret, generation, info)
    stream = hashlib.sha256(key + aad.encode()).digest()
    body = bytes(a ^ b for a, b in zip(plaintext.encode(), stream))
    tag = hmac.new(key, aad.encode() + body, hashlib.sha256).hexdigest()
    return {"body": body.hex(), "tag": tag, "generation": generation}


def open_record(secret, info, aad, record):
    expected = seal(secret, record["generation"], info, aad, bytes.fromhex(record["body"]).decode())
    return hmac.compare_digest(expected["tag"], record["tag"])
