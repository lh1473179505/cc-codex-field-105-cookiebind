import json
import uuid
from pathlib import Path

from .blobs import ContentStore
from .delegation import Delegations
from .plan import TargetPlan


class DelegationError(Exception):
    pass


class TargetRelease:
    def __init__(self, root, roles):
        self.root = Path(root)
        self.store = ContentStore(self.root / "blobs")
        self.plan = TargetPlan(self.root, self.store)
        self.delegations = Delegations(roles)
        self.journal = self.root / "releases.jsonl"
        self.journal.touch()

    def _event(self, tx, state, paths):
        with self.journal.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"tx": tx, "state": state, "paths": paths}) + "\n")

    def publish(self, targets, generation):
        tx = uuid.uuid4().hex
        self._event(tx, "staged", [item["path"] for item in targets])
        try:
            for item in targets:
                digest = self.plan.stage(item["path"], item["target"], generation)
                self.delegations.check(
                    item["path"], digest, item["role"], item["signature"],
                )
        except ValueError as error:
            self._event(tx, "aborted", [])
            raise DelegationError(str(error)) from error
        self.plan.seal(generation)
        self._event(tx, "sealed", [])

    def import_snapshot(self, snapshot, generation):
        targets = []
        for path, target in snapshot.items():
            digest = self.store.add(target)
            targets.append({
                "path": path,
                "target": target,
                "role": target["role"],
                "signature": __import__("tuftarget.delegation", fromlist=["signature"]).signature(
                    path, digest, target["role"], self.delegations.roles[target["role"]]
                ),
            })
        self.publish(targets, generation)
