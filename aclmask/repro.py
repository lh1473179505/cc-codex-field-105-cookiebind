import copy
import json
import tempfile
from .repository import Repository
from .bulk import apply_batch
from .migration import begin_move, finish_move
from .report import legacy_report

CHANGES = {
    "/srv/a": {"entries": {"user:alice": "rwx"}, "mask": "rwx"},
    "/srv/b": {"entries": {"group:ops": "rwx"}, "mask": "rwx"},
}

def main():
    checks = {}
    with tempfile.TemporaryDirectory() as tmp:
        repo = Repository(tmp)
        baseline = repo.snapshot()

        # 1. Failure on the second directory: the first object must be rolled
        # back as one snapshot (entries + mask together), so the effective
        # boundary never widens.
        result = apply_batch(repo, dict(CHANGES), refuse="/srv/b")
        report = legacy_report(repo)
        checks["second_directory_failure"] = {
            "status": result["status"],
            "object_restored": repo.state["objects"] == baseline,
            "report_view": report["/srv/a"],
            "effective_not_widened": report["/srv/a"]["alice_effective"] == "r--",
            "ok": (result["status"] == "rolled_back"
                   and repo.state["objects"] == baseline
                   and report["/srv/a"] == {"namespace": "pay", "mask": "r--",
                                            "alice_effective": "r--"}),
        }

        # 2. Namespace migration: the original path stays the diagnostic key
        # with unchanged namespace/mask/effective view until settle; object
        # rollback during migration also preserves the original boundary.
        alias = begin_move(repo, "/srv/a", "billing")
        migrating_report = legacy_report(repo)
        migrating_objects = copy.deepcopy(repo.state["objects"])
        apply_batch(repo, dict(CHANGES), refuse="/srv/b")
        during_migration = legacy_report(repo)
        rollback_restored = repo.state["objects"] == migrating_objects
        finish_move(repo, "/srv/a")
        settled_report = legacy_report(repo)
        checks["migration_query"] = {
            "alias": list(alias),
            "generation": repo.state["generation"],
            "original_path_diagnosis": migrating_report["/srv/a"],
            "rollback_keeps_original_namespace": (
                during_migration["/srv/a"]["namespace"] == "pay"
                and rollback_restored),
            "settled_namespace": settled_report["/srv/a"]["namespace"],
            "ok": (migrating_report["/srv/a"] == {"namespace": "pay", "mask": "r--",
                                                  "alice_effective": "r--"}
                   and alias[1] == "migrating"
                   and repo.state["generation"] == 2
                   and during_migration["/srv/a"]["namespace"] == "pay"
                   and rollback_restored
                   and settled_report["/srv/a"]["namespace"] == "billing"),
        }

        # 3. Repeated recovery: every failed batch ends rolled_back (never
        # committed), repeated restores converge on the same snapshot and the
        # read-only report keeps matching the stored boundary.
        settled_object = copy.deepcopy(repo.state["objects"]["/srv/a"])
        apply_batch(repo, dict(CHANGES), refuse="/srv/b")
        apply_batch(repo, dict(CHANGES), refuse="/srv/b")
        before_report = json.dumps(repo.state, sort_keys=True)
        final_report = legacy_report(repo)
        after_report = json.dumps(repo.state, sort_keys=True)
        checks["repeated_recovery"] = {
            "event_statuses": [event["status"] for event in repo.state["events"]],
            "never_committed": all(event["status"] == "rolled_back"
                                   for event in repo.state["events"]),
            "object_restored": repo.state["objects"]["/srv/a"] == settled_object,
            "report_consistent": (final_report["/srv/a"]["mask"]
                                  == repo.state["objects"]["/srv/a"]["mask"]
                                  and final_report["/srv/a"]["alice_effective"] == "r--"),
            "report_read_only": before_report == after_report,
            "ok": (all(event["status"] == "rolled_back"
                       for event in repo.state["events"])
                   and repo.state["objects"]["/srv/a"] == settled_object
                   and final_report["/srv/a"] == {"namespace": "billing", "mask": "r--",
                                                  "alice_effective": "r--"}),
        }

    all_ok = all(scenario["ok"] for scenario in checks.values())
    print(json.dumps({"ok": all_ok, "checks": checks}, sort_keys=True, indent=2))
    return 0 if all_ok else 1
