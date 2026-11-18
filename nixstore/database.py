import json
from pathlib import Path


class RegistrationDB:
    def __init__(self, root):
        self.path = Path(root) / "registrations.json"
        if not self.path.exists():
            self.save({})

    def all(self):
        return json.loads(self.path.read_text())

    def save(self, value):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, sort_keys=True))
        temporary.replace(self.path)

    def register(self, name, digest, generation):
        value = self.all()
        value[name] = {"digest": digest, "generation": generation, "valid": True}
        self.save(value)

    def unregister(self, name):
        value = self.all()
        value.pop(name, None)
        self.save(value)
