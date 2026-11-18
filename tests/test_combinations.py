import unittest
from perfevent.counters import Counters
from perfevent.groups import Groups
from perfevent.arming import arm, ArmInterrupt
from perfevent.recovery import recover

class CombinationTests(unittest.TestCase):
    def test_cancel_after_interrupt_is_not_rearmed(self):
        counters = Counters()
        groups = Groups(counters)
        groups.create("sched", [0, 1])
        with self.assertRaises(ArmInterrupt):
            arm(groups, "sched", interrupt=True)
        groups.cancel("sched")
        self.assertEqual(recover(groups), [])
        self.assertEqual(groups.items["sched"]["state"], "cancelled")
        self.assertEqual(counters.units, {0: 0, 1: 0})

    def test_normal_arm_is_recoverable(self):
        counters = Counters()
        groups = Groups(counters)
        groups.create("sched", [0])
        arm(groups, "sched")
        self.assertEqual(groups.items["sched"]["state"], "armed")

if __name__ == "__main__":
    unittest.main()
