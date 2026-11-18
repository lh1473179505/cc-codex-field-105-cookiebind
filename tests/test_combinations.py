import copy
import tempfile
import unittest
from filecaps.store import Store
from filecaps.coordinator import publish
from filecaps.legacy import audit_snapshot

class CombinationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(self.tmp.name)
        self.store.data["leases"]["ops-1"] = {"epoch": 1}

    def tearDown(self):
        self.tmp.cleanup()

    def test_failed_second_node_restores_exact_sets(self):
        publish(self.store, {"alpha": ["cap_net_admin"], "beta": ["cap_net_raw"]}, fail_on="beta")
        self.assertEqual(self.store.data["nodes"]["alpha"],
                         {"permitted": ["cap_net_raw"], "effective": ["cap_net_raw"]})

    def test_audit_does_not_change_recovery_state(self):
        before = copy.deepcopy(self.store.data)
        audit_snapshot(self.store)
        self.assertEqual(self.store.data, before)

if __name__ == "__main__":
    unittest.main()
