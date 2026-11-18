class LegacyAudit:
    """The v1 consumer exposes a dense prefix, not an allocation watermark."""
    def __init__(self, service):
        self.service = service

    def export(self):
        checkpoint = self.service.checkpoints.load()
        indexes = [entry["index"] for entry in checkpoint["entries"]]
        if indexes != list(range(checkpoint["head"])):
            missing = sorted(set(range(checkpoint["head"])) - set(indexes))
            raise ValueError("legacy checkpoint gap: " + ",".join(map(str, missing)))
        return {"version": 1, "head": checkpoint["head"], "entries": checkpoint["entries"]}
