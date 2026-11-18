import tempfile

from kanikox.bootstrap import BootstrapRecovery
from kanikox.compat import LegacyResolver
from kanikox.publisher import Publisher


with tempfile.TemporaryDirectory() as tmp:
    publisher = Publisher(tmp)
    for number in range(10):
        latest = publisher.push("stable", {"version": str(number)})
    resolver = LegacyResolver(publisher)
    assert resolver.snapshot()["stable"] == latest
    BootstrapRecovery(publisher).restore()
    restored = resolver.snapshot()["stable"]
    assert restored != latest
    assert publisher.destinations.all()["stable"]["sequence"] == 9
    print("REPRODUCED: lexical journal replay rolled a destination back to sequence 9")
