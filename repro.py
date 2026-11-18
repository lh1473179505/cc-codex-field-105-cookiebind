import tempfile

from buildkit.exporter import CacheExporter, ExportError
from buildkit.reader import LegacyCacheReader
from buildkit.recovery import CacheRecovery


with tempfile.TemporaryDirectory() as tmp:
    exporter = CacheExporter(tmp)
    exporter.export("stable", ["shared-layer"])
    try:
        exporter.export("candidate", ["shared-layer", "new-layer"], "bad")
    except ExportError:
        pass
    CacheRecovery(exporter).collect()
    try:
        LegacyCacheReader(exporter).open("stable")
    except FileNotFoundError:
        print("REPRODUCED: rollback released a stable cache layer and recovery collected it")
    else:
        raise AssertionError("baseline defect did not reproduce")
