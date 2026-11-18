import tempfile
import unittest

from buildahx.builder import Builder, BuildError
from buildahx.inspect import LegacyInspect
from buildahx.layers import LayerStore, seal
from buildahx.recover import BuildRecovery


class ReplayAtomicityTest(unittest.TestCase):
    def test_aborted_layer_is_not_resurrected(self):
        with tempfile.TemporaryDirectory() as tmp:
            builder = Builder(tmp)
            layer = LayerStore(tmp + "/probe").add("one")
            with self.assertRaises(BuildError):
                builder.commit(["one", "two"], [seal(layer, 1, "build-secret"), "bad"])
            BuildRecovery(builder).replay()
            self.assertEqual(LegacyInspect(builder).image()["Layers"], [])


if __name__ == "__main__":
    unittest.main()
