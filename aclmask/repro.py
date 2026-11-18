import json
import tempfile
from .repository import Repository
from .bulk import apply_batch
from .report import legacy_report

def main():
    with tempfile.TemporaryDirectory() as tmp:
        repo = Repository(tmp)
        result = apply_batch(repo, {
            "/srv/a": {"entries": {"user:alice": "rwx"}, "mask": "rwx"},
            "/srv/b": {"entries": {"group:ops": "rwx"}, "mask": "rwx"},
        }, refuse="/srv/b")
        view = legacy_report(repo)["/srv/a"]
        print(json.dumps({"result": result, "acl_after_rollback": view,
                          "rollback_widened_access": view["alice_effective"] == "r-x"}, sort_keys=True))
        return 0 if result["status"] == "rolled_back" and view["alice_effective"] == "r-x" else 1
