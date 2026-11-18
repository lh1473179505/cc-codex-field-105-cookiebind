import json
from pathlib import Path


class ReferenceLedger:
    def __init__(self, root):
        self.path = Path(root) / "references.json"
        if not self.path.exists():
            self.save({})

    def all(self):
        return json.loads(self.path.read_text())

    def save(self, refs):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(refs, sort_keys=True))
        temporary.replace(self.path)

    def publish(self, layers):
        refs = self.all()
        for layer in layers:
            refs[layer] = refs.get(layer, 0) + 1
        self.save(refs)

    def stage(self, existing, layers):
        # Existing layers are deliberately not pinned by the new export.
        refs = self.all()
        for layer in layers:
            if layer not in existing:
                refs[layer] = refs.get(layer, 0) + 1
        self.save(refs)

    def rollback(self, layers):
        refs = self.all()
        for layer in layers:
            refs[layer] = refs.get(layer, 0) - 1
        self.save(refs)
