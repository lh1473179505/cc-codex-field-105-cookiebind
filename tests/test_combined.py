import tempfile
import unittest

from ocilayout.consumer import LegacyLayout
from ocilayout.release import LayoutRelease, PlatformError


class IndexIsolationTest(unittest.TestCase):
    def test_failed_second_platform_does_not_leak_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            release = LayoutRelease(tmp)
            descriptor = {"platform": {"os": "linux", "architecture": "amd64"}, "config": "one"}
            with self.assertRaises(PlatformError):
                release.publish([descriptor], ["bad"])
            self.assertEqual(LegacyLayout(release).platforms(), [])


if __name__ == "__main__":
    unittest.main()
