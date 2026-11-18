import hmac
import uuid
from pathlib import Path

from .journal import BuildJournal
from .layers import LayerStore, seal
from .manifest import Manifest


class BuildError(Exception):
    pass


class Builder:
    def __init__(self, root, secret="build-secret"):
        self.root = Path(root)
        self.layers = LayerStore(self.root / "layers")
        self.journal = BuildJournal(self.root)
        self.manifest = Manifest(self.root)
        self.secret = secret

    def commit(self, contents, signatures, epoch=1):
        tx = uuid.uuid4().hex
        before = self.manifest.read()["layers"]
        added = []
        self.journal.append(tx, "prepared")
        try:
            for content, supplied in zip(contents, signatures):
                layer = self.layers.add(content)
                expected = seal(layer, epoch, self.secret)
                if not hmac.compare_digest(expected, supplied):
                    raise BuildError("layer seal mismatch")
                added.append(layer)
                self.manifest.replace_layers(before + added)
                self.journal.append(tx, "layer-committed", layer)
        except BuildError:
            self.manifest.replace_layers(before)
            self.journal.append(tx, "aborted")
            raise
        self.journal.append(tx, "committed")
        return added

    def import_image(self, contents, signatures, epoch=1):
        # Full image import uses the same journal but starts from an empty base.
        before = self.manifest.read()["layers"]
        self.manifest.replace_layers([])
        try:
            return self.commit(contents, signatures, epoch)
        except BuildError:
            self.manifest.replace_layers(before)
            raise
