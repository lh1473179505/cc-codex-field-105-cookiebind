import tempfile
import unittest
from pathlib import Path

from rekorlog.audit import LegacyAudit
from rekorlog.entries import sign
from rekorlog.service import LogService, ReleaseError


class CombinedReleaseTest(unittest.TestCase):
    def test_abort_retry_and_recover_keep_dense_legacy_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            service = LogService(Path(tmp), {"publisher": "secret"})
            good = sign("sha256:aaa", "publisher", "secret")
            bad = sign("sha256:bbb", "publisher", "secret")
            bad.signature = "0" * 64
            with self.assertRaises(ReleaseError):
                service.append([good, bad])
            service.append([sign("sha256:ccc", "publisher", "secret")])
            service.recover()
            exported = LegacyAudit(service).export()
            self.assertEqual(exported["head"], 1)
            self.assertEqual(exported["entries"][0]["index"], 0)


if __name__ == "__main__":
    unittest.main()
