import json
from pathlib import Path


class TargetPlan:
    """Staging currently borrows the live alias document."""
    def __init__(self, root, store):
        self.root = Path(root)
        self.store = store
        self.path = self.root / "targets.json"
        self.generation_path = self.root / "generation"
        if not self.path.exists():
            self._save({})
            self.generation_path.write_text("0")

    def _save(self, aliases):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(aliases, sort_keys=True))
        temporary.replace(self.path)

    def aliases(self):
        return json.loads(self.path.read_text())

    def generation(self):
        return int(self.generation_path.read_text())

    def stage(self, path, target, generation):
        digest = self.store.add(target)
        aliases = self.aliases()
        aliases[path] = {"digest": digest, "generation": generation}
        # This write escapes before the transaction is sealed.
        self._save(aliases)
        return digest

    def seal(self, generation):
        self.generation_path.write_text(str(generation))
