import tempfile
import unittest

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


class IndexIsolationTest(unittest.TestCase):
    def test_failed_second_platform_does_not_leak_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            release = LayoutRelease(tmp)
            descriptor = {"platform": {"os": "linux", "architecture": "amd64"}, "config": "one"}
            with self.assertRaises(PlatformError):
                release.publish([descriptor], ["bad"])
            self.assertEqual(LegacyLayout(release).platforms(), [])

    def test_aborted_batch_preserves_previous_sealed_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            release = LayoutRelease(tmp)
            amd64 = {"platform": {"os": "linux", "architecture": "amd64"}, "config": "one"}
            arm64 = {"platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}, "config": "two"}
            release.publish([amd64], [signed(release, amd64)])
            before = release.index.read()
            with self.assertRaises(PlatformError):
                release.publish([arm64, amd64], [signed(release, arm64), "bad"])
            self.assertEqual(release.index.read(), before)
            self.assertEqual(LegacyLayout(release).platforms(), ["linux/amd64"])
            self.assertEqual(LayoutRecovery(release).compact(), {"aborted": 1})

    def test_retry_after_abort_seals_complete_new_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            release = LayoutRelease(tmp)
            amd64 = {"platform": {"os": "linux", "architecture": "amd64"}, "config": "one"}
            arm64 = {"platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}, "config": "two"}
            with self.assertRaises(PlatformError):
                release.import_index([amd64, arm64], [signed(release, amd64), "bad"])
            release.import_index([amd64, arm64], [signed(release, amd64), signed(release, arm64)])
            self.assertEqual(LegacyLayout(release).platforms(), ["linux/amd64", "linux/arm64"])

    def test_staging_array_is_not_shared_with_readers(self):
        with tempfile.TemporaryDirectory() as tmp:
            release = LayoutRelease(tmp)
            amd64 = {"platform": {"os": "linux", "architecture": "amd64"}, "config": "one"}
            release.publish([amd64], [signed(release, amd64)])
            snapshot = release.index.read()
            working = release.index.mutable_working_copy()
            working["manifests"].append({"platform": {"os": "linux", "architecture": "arm64"}})
            self.assertEqual(release.index.read(), snapshot)
            self.assertEqual(len(snapshot["manifests"]), 1)

    def test_legacy_descriptor_returns_digest_size_and_matches_variant(self):
        with tempfile.TemporaryDirectory() as tmp:
            release = LayoutRelease(tmp)
            arm64 = {"platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}, "config": "two"}
            release.publish([arm64], [signed(release, arm64)])
            legacy = LegacyLayout(release)
            self.assertEqual(sorted(legacy.descriptor("linux", "arm64", "v8")), ["digest", "size"])
            with self.assertRaises(KeyError):
                legacy.descriptor("linux", "arm64")


if __name__ == "__main__":
    unittest.main()
