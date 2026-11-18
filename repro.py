import tempfile

from buildahx.builder import Builder, BuildError
from buildahx.inspect import LegacyInspect
from buildahx.layers import LayerStore, seal
from buildahx.recover import BuildRecovery


with tempfile.TemporaryDirectory() as tmp:
    builder = Builder(tmp)
    first = LayerStore(tmp + "/probe").add("one")
    try:
        builder.commit(["one", "two"], [seal(first, 1, "build-secret"), "bad"])
    except BuildError:
        pass
    assert LegacyInspect(builder).image()["Layers"] == []
    BuildRecovery(builder).replay()
    assert LegacyInspect(builder).image()["Layers"] == [first]
    print("REPRODUCED: replay resurrected a layer from an aborted build")
