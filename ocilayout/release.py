import json
from pathlib import Path

from .blobs import BlobStore
from .index import ImageIndex
from .platforms import PlatformVerifier


class PlatformError(Exception):
    pass


class LayoutRelease:
    def __init__(self, root, secret="oci-secret"):
        self.root = Path(root)
        self.blobs = BlobStore(self.root / "blobs" / "sha256")
        self.index = ImageIndex(self.root)
        self.verifier = PlatformVerifier(secret)
        self.journal = self.root / "layout-events.jsonl"
        self.journal.touch()

    def publish(self, descriptors, signatures):
        working = self.index.mutable_working_copy()
        self.journal.write_text(self.journal.read_text() + json.dumps({"state": "staged"}) + "\n")
        try:
            for descriptor, signature in zip(descriptors, signatures):
                stored = self.blobs.put(descriptor)
                stored["platform"] = descriptor["platform"]
                stored["mediaType"] = descriptor.get("mediaType", "application/vnd.oci.image.manifest.v1+json")
                self.verifier.verify(stored, signature)
                working["manifests"].append(stored)
                self.index.write(working)
        except ValueError as error:
            self.journal.write_text(self.journal.read_text() + json.dumps({"state": "aborted"}) + "\n")
            raise PlatformError(str(error)) from error
        self.journal.write_text(self.journal.read_text() + json.dumps({"state": "sealed"}) + "\n")

    def import_index(self, descriptors, signatures):
        return self.publish(descriptors, signatures)
