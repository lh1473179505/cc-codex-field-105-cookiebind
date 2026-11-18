from .model import Artifact, ReleaseState
from .releasestore import Store
from .signature import artifact_signature


class Service:
    def __init__(self, workspace):
        self.store = Store(workspace)
        self.generation = 1
        self.keys = {1: b"minisign-release-key-v1"}
        self.artifacts = {}

    def load(self, identifier, content):
        self.artifacts[identifier] = Artifact(identifier, content, self.generation)
        self.store.append("artifact_loaded", identifier=identifier, generation=self.generation)

    def rotate(self, secret):
        self.generation += 1
        self.keys[self.generation] = secret
        self.store.append("release_key_rotated", generation=self.generation)

    def sign(self, identifier, comment="timestamp:2026-06-18 artifact:pay-release", fail_after=False):
        artifact = self.artifacts[identifier]
        generation = artifact.generation
        value = artifact_signature(self.keys[generation], identifier, artifact.content, comment)
        if fail_after:
            raise ValueError("secondary signature publication failed")
        artifact.signatures.append({"generation": generation, "signature": value})
        artifact.state = ReleaseState.SIGNED
        self.store.append("artifact_signed", identifier=identifier, generation=generation, signature=value)
        return value

    def abort(self, identifier):
        self.artifacts[identifier].state = ReleaseState.WITHDRAWN

    def publish(self, identifier):
        artifact = self.artifacts[identifier]
        if not artifact.signatures:
            raise ValueError("unsigned artifact")
        artifact.state = ReleaseState.PUBLISHED
        return {"artifact": identifier, "signatures": list(artifact.signatures)}

    def audit(self):
        return {"states": {k: v.state.value for k, v in self.artifacts.items()}}
