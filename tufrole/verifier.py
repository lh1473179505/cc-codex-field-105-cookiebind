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
        # A prepared transaction is pinned to the signing epoch it captured.
        # Rotation only constrains new transactions; already prepared work is
        # authenticated against the keys and revocation set of that epoch.
        if epoch is None:
            epoch, current = self.epochs.current()
        else:
            current = self.epochs.at(epoch)
        if role.name in current["revoked"]:
            raise VerificationError(f"role revoked in epoch {epoch}")
        secret = current["keys"].get(role.name)
        expected = hmac.new(
            (secret or "").encode(),
            payload_bytes(role.name, role.version, role.epoch, role.envelope),
            hashlib.sha256,
        ).hexdigest()
        if not secret or not hmac.compare_digest(expected, role.signature):
            raise VerificationError(f"signature is not valid in epoch {epoch}")

    def from_record(self, record):
        return Role(
            record["name"], record["version"], record["epoch"],
            record["signature"], record["envelope"],
        )
