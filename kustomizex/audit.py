import json


class LegacyAudit:
    def __init__(self, pipeline):
        self.pipeline = pipeline

    def current(self):
        release = json.loads(self.pipeline.path.read_text())
        signing = self.pipeline.signing.state()
        if release["digest"] is not None and release["epoch"] in signing["revoked"]:
            raise RuntimeError("legacy audit found a release from a revoked epoch")
        return {
            "sequence": release["sequence"],
            "digest": release["digest"],
            "resources": [item["metadata"]["name"] for item in release.get("documents", [])],
        }
