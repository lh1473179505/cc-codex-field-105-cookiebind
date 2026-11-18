class LegacyBundle:
    def __init__(self, release):
        self.release = release

    def export(self):
        entries = []
        for name, record in sorted(self.release.db.all().items()):
            path = self.release.nar.path(name)
            if not path.exists():
                raise RuntimeError("registered store path is missing: " + name)
            entries.append({"path": "/nix/store/" + name, "sha256": record["digest"]})
        return {"format": 1, "entries": entries}
