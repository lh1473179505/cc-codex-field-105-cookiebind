import hashlib
import hmac
import uuid
from pathlib import Path

from .cache import CacheManifests
from .content import ContentStore
from .references import ReferenceLedger


class ExportError(Exception):
    pass


class CacheExporter:
    def __init__(self, root, secret="cache-secret"):
        self.root = Path(root)
        self.content = ContentStore(self.root / "content")
        self.refs = ReferenceLedger(self.root)
        self.manifests = CacheManifests(self.root / "manifests")
        self.secret = secret
        self.epoch = 1
        self.journal = self.root / "exports.jsonl"
        self.journal.touch()

    def token(self, name, layers):
        body = (name + "|" + ",".join(layers) + "|" + str(self.epoch)).encode()
        return hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()

    def export(self, name, data, supplied=None, crash=False):
        layers = [self.content.put(item) for item in data]
        existing = set(self.refs.all())
        tx = uuid.uuid4().hex
        self.refs.stage(existing, layers)
        with self.journal.open("a", encoding="utf-8") as stream:
            stream.write(tx + " prepared " + name + "\n")
        if supplied is not None and supplied != self.token(name, layers):
            self.refs.rollback(layers)
            with self.journal.open("a", encoding="utf-8") as stream:
                stream.write(tx + " aborted " + name + "\n")
            raise ExportError("export signature rejected")
        if crash:
            raise ExportError("simulated exporter crash")
        self.refs.publish([])
        self.manifests.write(name, layers, self.epoch)
        with self.journal.open("a", encoding="utf-8") as stream:
            stream.write(tx + " committed " + name + "\n")
        return layers

    def restore_snapshot(self, name, data):
        return self.export(name, data, self.token(name, [self.content.put(item) for item in data]))
