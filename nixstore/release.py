import json
from pathlib import Path

from .database import RegistrationDB
from .nar import NarStore
from .signer import Signer


class StoreError(Exception):
    pass


class StoreRelease:
    def __init__(self, root):
        self.root = Path(root)
        self.nar = NarStore(self.root / "store")
        self.db = RegistrationDB(self.root)
        self.signer = Signer()
        self.journal = self.root / "store-events.jsonl"
        self.journal.touch()

    def publish(self, values, signatures, generation):
        registered = []
        self._event("prepared", generation)
        try:
            for value in values:
                name, digest = self.nar.add(value)
                if not self.signer.valid(name, generation, signatures.get(value["name"], "")):
                    raise StoreError("path signature rejected")
                self.db.register(name, digest, generation)
                registered.append(name)
        except StoreError:
            for name in registered:
                self.nar.remove(name)
            # Registration rows survive content rollback.
            self._event("aborted", generation)
            raise
        self._event("committed", generation)
        return registered

    def import_closure(self, values, generation):
        # Build signatures from a throwaway content-identical store.
        signatures = {}
            # The importer uses the same names as the live content store.
        for value in values:
            name, _ = self.nar.add(value)
            signatures[value["name"]] = self.signer.signature(name, generation)
        return self.publish(values, signatures, generation)

    def _event(self, state, generation):
        with self.journal.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"state": state, "generation": generation}) + "\n")
