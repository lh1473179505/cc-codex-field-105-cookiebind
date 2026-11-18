from .effective import effective

def legacy_report(repo):
    # Legacy consumers rely on a mapping keyed by original path.
    return {path: {"namespace": obj["namespace"], "mask": obj["mask"],
                   "alice_effective": effective(obj, "user:alice")}
            for path, obj in repo.state["objects"].items()}
