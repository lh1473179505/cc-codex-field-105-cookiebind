import copy
import tempfile
import unittest
from aclmask.repository import Repository
from aclmask.bulk import apply_batch
from aclmask.migration import begin_move, finish_move
from aclmask.report import legacy_report

class CombinationTests(unittest.TestCase):
    def test_rollback_preserves_mask_and_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(tmp)
            apply_batch(repo, {
                "/srv/a": {"entries": {"user:alice": "rwx"}, "mask": "rwx"},
                "/srv/b": {"entries": {"group:ops": "rwx"}, "mask": "rwx"},
            }, refuse="/srv/b")
            self.assertEqual(repo.state["objects"]["/srv/a"],
                             {"entries": {"user:alice": "r-x"}, "mask": "r--", "namespace": "pay"})
            self.assertEqual(legacy_report(repo)["/srv/a"]["alice_effective"], "r--")

    def test_legacy_report_is_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(tmp)
            before = copy.deepcopy(repo.state)
            legacy_report(repo)
            self.assertEqual(repo.state, before)

    def test_migration_keeps_original_path_diagnosis(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(tmp)
            alias = begin_move(repo, "/srv/a", "billing")
            self.assertEqual(alias[1], "migrating")
            self.assertEqual(repo.state["generation"], 2)
            view = legacy_report(repo)["/srv/a"]
            self.assertEqual(view, {"namespace": "pay", "mask": "r--",
                                    "alice_effective": "r--"})
            apply_batch(repo, {
                "/srv/a": {"entries": {"user:alice": "rwx"}, "mask": "rwx"},
                "/srv/b": {"entries": {"group:ops": "rwx"}, "mask": "rwx"},
            }, refuse="/srv/b")
            self.assertEqual(repo.state["objects"]["/srv/a"]["namespace"], "pay")
            finish_move(repo, "/srv/a")
            self.assertEqual(legacy_report(repo)["/srv/a"]["namespace"], "billing")

    def test_repeated_rollback_converges_and_never_commits(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Repository(tmp)
            baseline = copy.deepcopy(repo.state["objects"]["/srv/a"])
            for _ in range(3):
                result = apply_batch(repo, {
                    "/srv/a": {"entries": {"user:alice": "rwx"}, "mask": "rwx"},
                    "/srv/b": {"entries": {"group:ops": "rwx"}, "mask": "rwx"},
                }, refuse="/srv/b")
                self.assertEqual(result["status"], "rolled_back")
                self.assertEqual(repo.state["objects"]["/srv/a"], baseline)
            self.assertTrue(all(event["status"] == "rolled_back"
                                for event in repo.state["events"]))
            self.assertEqual(legacy_report(repo)["/srv/a"]["alice_effective"], "r--")

if __name__ == "__main__":
    unittest.main()
