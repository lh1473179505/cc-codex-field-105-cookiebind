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

    def stage(self, layers):
        refs = self.all()
        for layer in layers:
            refs[layer] = refs.get(layer, 0) + 1
        self.save(refs)

    def rollback(self, layers):
        refs = self.all()
        for layer in layers:
            count = refs.get(layer, 0) - 1
            if count > 0:
                refs[layer] = count
            else:
                refs.pop(layer, None)
        self.save(refs)

    def reconcile(self, required):
        self.save({layer: count for layer, count in required.items() if count > 0})
