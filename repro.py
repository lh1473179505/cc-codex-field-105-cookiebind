import tempfile

from ocilayout.blobs import BlobStore
from ocilayout.consumer import LegacyLayout
from ocilayout.platforms import approve
from ocilayout.recovery import LayoutRecovery
from ocilayout.release import LayoutRelease, PlatformError


def signed(release, descriptor):
    stored = BlobStore(release.root / "probe").put(descriptor)
    stored["platform"] = descriptor["platform"]
    stored["mediaType"] = "application/vnd.oci.image.manifest.v1+json"
    return approve(stored, "oci-secret")


with tempfile.TemporaryDirectory() as tmp:
    release = LayoutRelease(tmp)
    first = {"platform": {"os": "linux", "architecture": "amd64"}, "config": "one"}
    second = {"platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}, "config": "two"}

    # arm64 approval fails mid-batch: the public index must stay untouched.
    try:
        release.publish([first, second], [signed(release, first), "bad"])
    except PlatformError:
        pass
    legacy = LegacyLayout(release)
    assert legacy.platforms() == [], legacy.platforms()
    assert LayoutRecovery(release).compact() == {"aborted": 1}

    # Retry with a fully approved batch: only the complete new index appears.
    release.import_index([first, second], [signed(release, first), signed(release, second)])
    assert legacy.platforms() == ["linux/amd64", "linux/arm64"], legacy.platforms()

    # Legacy lookup returns only digest/size; platform variant stays significant.
    found = legacy.descriptor("linux", "arm64", "v8")
    assert sorted(found) == ["digest", "size"], found
    try:
        legacy.descriptor("linux", "arm64")
    except KeyError:
        pass
    else:
        raise AssertionError("variant-less lookup must not match linux/arm64/v8")
    print("OK: aborted batch left no staged descriptor; sealed batch is complete")
