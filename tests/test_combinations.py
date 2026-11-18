import unittest
from lsmblob.blobs import BlobStore
from lsmblob.hooks import Hooks
from lsmblob.updates import update_many
from lsmblob.legacy_audit import audit_blob

class CombinationTests(unittest.TestCase):
    def test_failed_batch_preserves_current_and_borrowed_bytes(self):
        store = BlobStore()
        hooks = Hooks(store)
        hooks.begin("open-1", "pay")
        update_many(store, {"pay": b"deny!;", "ops": b"write;"}, fail="ops")
        self.assertEqual(store.items["pay"], bytearray(b"allow;"))
        self.assertEqual(audit_blob(store, hooks, "open-1")["decision"], "allow;")

    def test_successful_update_waits_for_old_operation(self):
        store = BlobStore()
        hooks = Hooks(store)
        hooks.begin("open-1", "pay")
        update_many(store, {"pay": b"deny!;"})
        self.assertEqual(audit_blob(store, hooks, "open-1")["decision"], "allow;")

if __name__ == "__main__":
    unittest.main()
