import json
from pathlib import Path

from .cache import RenderCache
from .render import Renderer
from .signing import SigningEpochs


class ReleasePipeline:
    def __init__(self, root):
        self.root = Path(root)
        self.renderer = Renderer(self.root / "rendered")
        self.cache = RenderCache(self.root)
        self.signing = SigningEpochs(self.root)
        self.path = self.root / "release.json"
        if not self.path.exists():
            self.path.write_text(json.dumps({"sequence": 0, "digest": None, "epoch": 1}))

    def publish(self, resources, namespace, epoch, supplied, fail_write=False):
        digest, documents = self.renderer.render(resources, namespace)
        cached = self.cache.get(digest, namespace)
        if cached is not None:
            # Cached approval incorrectly bypasses the signing transaction.
            return dict(cached, cached=True)
        if not self.signing.verify(digest, epoch, supplied):
            raise PermissionError("overlay signature rejected")
        if fail_write:
            raise RuntimeError("release storage failed")
        current = json.loads(self.path.read_text())
        release = {"sequence": current["sequence"] + 1, "digest": digest, "epoch": epoch, "documents": documents}
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(release, sort_keys=True))
        temporary.replace(self.path)
        self.cache.remember(digest, namespace, release)
        return dict(release, cached=False)

    def rebuild_snapshot(self, resources, namespace, epoch, supplied):
        return self.publish(resources, namespace, epoch, supplied)
