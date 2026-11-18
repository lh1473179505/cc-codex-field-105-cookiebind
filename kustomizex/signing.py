import hashlib
import hmac
import json
from pathlib import Path


def signature(digest, epoch, secret):
    return hmac.new(secret.encode(), (digest + "|" + str(epoch)).encode(), hashlib.sha256).hexdigest()


class SigningEpochs:
    def __init__(self, root):
        self.path = Path(root) / "signing.json"
        if not self.path.exists():
            self.path.write_text(json.dumps({"epoch": 1, "keys": {"1": "overlay-one", "2": "overlay-two"}, "revoked": []}))

    def state(self):
        return json.loads(self.path.read_text())

    def rotate(self, epoch):
        state = self.state()
        state["revoked"].append(state["epoch"])
        state["epoch"] = epoch
        self.path.write_text(json.dumps(state, sort_keys=True))

    def verify(self, digest, epoch, supplied):
        state = self.state()
        if epoch in state["revoked"] or epoch > state["epoch"]:
            return False
        expected = signature(digest, epoch, state["keys"][str(epoch)])
        return hmac.compare_digest(expected, supplied)
