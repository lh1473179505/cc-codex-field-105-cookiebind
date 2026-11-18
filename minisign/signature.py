import hashlib
import hmac


def digest(content):
    return hashlib.sha256(content).hexdigest()


def artifact_signature(secret, artifact, content, trusted_comment):
    message = artifact.encode() + bytes.fromhex(digest(content)) + trusted_comment.encode()
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def legacy_comment(comment):
    if comment.startswith("timestamp:") and " artifact:" not in comment:
        return comment + " artifact:legacy"
    return comment
