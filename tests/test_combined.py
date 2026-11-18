import tempfile
import unittest

from kustomizex.release import ReleasePipeline
from kustomizex.signing import signature


class EpochCacheTest(unittest.TestCase):
    def test_revoked_signature_cannot_reuse_cached_publication(self):
        with tempfile.TemporaryDirectory() as tmp:
            pipeline = ReleasePipeline(tmp)
            resources = [{"metadata": {"name": "app"}}]
            digest, _ = pipeline.renderer.render(resources, "prod")
            pipeline.publish(resources, "prod", 1, signature(digest, 1, "overlay-one"))
            pipeline.signing.rotate(2)
            with self.assertRaises(PermissionError):
                pipeline.publish(resources, "prod", 1, signature(digest, 1, "overlay-one"))
            self.assertEqual(pipeline.cache.get(digest, "prod")["sequence"], 1)


if __name__ == "__main__":
    unittest.main()
