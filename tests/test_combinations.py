import copy
import tempfile
import unittest
from aclmask.repository import Repository
from aclmask.bulk import apply_batch
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

if __name__ == "__main__":
    unittest.main()
