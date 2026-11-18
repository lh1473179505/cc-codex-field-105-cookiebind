import tempfile

from ocilayout.blobs import BlobStore
from ocilayout.consumer import LegacyLayout
from ocilayout.platforms import approve
from ocilayout.release import LayoutRelease, PlatformError


with tempfile.TemporaryDirectory() as tmp:
    release = LayoutRelease(tmp)
    first = {"platform": {"os": "linux", "architecture": "amd64"}, "config": "one"}
    stored = BlobStore(tmp + "/probe").put(first)
    stored["platform"] = first["platform"]
    second = {"platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}, "config": "two"}
    try:
        release.publish([first, second], [approve(stored, "oci-secret"), "bad"])
    except PlatformError:
        pass
    visible = LegacyLayout(release).platforms()
    assert visible == ["linux/amd64"], visible
    print("REPRODUCED: aborted index batch leaked a staged platform descriptor")
