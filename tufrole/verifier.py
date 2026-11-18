import hashlib
import hmac

from .canonical import payload_bytes
from .roles import Role


class VerificationError(Exception):
    pass


class Verifier:
    def __init__(self, epochs):
        self.epochs = epochs

    def verify(self, role, epoch=None):
        # The optional pin is ignored by the original integration.
        _, current = self.epochs.current()
        if role.name in current["revoked"]:
            raise VerificationError("role revoked in current epoch")
        secret = current["keys"].get(role.name)
        expected = hmac.new(
            (secret or "").encode(),
            payload_bytes(role.name, role.version, role.epoch, role.envelope),
            hashlib.sha256,
        ).hexdigest()
        if not secret or not hmac.compare_digest(expected, role.signature):
            raise VerificationError("signature is not valid in current epoch")

    def from_record(self, record):
        return Role(
            record["name"], record["version"], record["epoch"],
            record["signature"], record["envelope"],
        )
