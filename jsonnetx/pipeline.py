import hashlib
import hmac
from pathlib import Path

from .evaluator import Evaluator
from .imports import ImportClosure
from .transaction import OutputTransaction


class RenderError(Exception):
    pass


class RenderPipeline:
    def __init__(self, root, secret="render-secret"):
        self.root = Path(root)
        self.closures = ImportClosure(self.root / "closures")
        self.evaluator = Evaluator()
        self.secret = secret

    def token(self, manifest, epoch):
        body = "|".join([str(epoch)] + [path + ":" + manifest[path] for path in sorted(manifest)])
        return hmac.new(self.secret.encode(), body.encode(), hashlib.sha256).hexdigest()

    def publish(self, imports, outputs, epoch=1, signatures=None):
        closure_digest, closure = self.closures.freeze(imports)
        rendered, manifest = self.evaluator.evaluate(closure, outputs)
        transaction = OutputTransaction(self.root)
        signatures = signatures or {}
        try:
            for path in sorted(rendered):
                expected = self.token({path: manifest[path]}, epoch)
                if signatures.get(path) != expected:
                    raise RenderError("output signature mismatch")
                transaction.stage(path, rendered[path])
        except RenderError:
            transaction.rollback()
            raise
        transaction.commit()
        return {"closure": closure_digest, "manifest": manifest}

    def publish_bundle(self, imports, outputs, epoch=1):
        _, closure = self.closures.freeze(imports)
        _, manifest = self.evaluator.evaluate(closure, outputs)
        signatures = {
            path: self.token({path: manifest[path]}, epoch)
            for path in manifest
        }
        return self.publish(imports, outputs, epoch, signatures)
