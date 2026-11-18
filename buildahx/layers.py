import hashlib
import hmac
import json
from pathlib import Path


class LayerStore:
    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def add(self, content):
        key = hashlib.sha256(content.encode()).hexdigest()
        path = self.root / key[:2] / (key + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"digest": key, "content": content}, sort_keys=True))
        return key


def seal(layer, epoch, secret):
    return hmac.new(secret.encode(), (layer + "|" + str(epoch)).encode(), hashlib.sha256).hexdigest()
