import tempfile

from kustomizex.release import ReleasePipeline
from kustomizex.signing import signature


with tempfile.TemporaryDirectory() as tmp:
    pipeline = ReleasePipeline(tmp)
    resources = [{"metadata": {"name": "app"}}]
    digest, _ = pipeline.renderer.render(resources, "prod")
    old_signature = signature(digest, 1, "overlay-one")
    pipeline.publish(resources, "prod", 1, old_signature)
    pipeline.signing.rotate(2)
    replay = pipeline.publish(resources, "prod", 1, old_signature)
    assert replay["cached"] is True
    print("REPRODUCED: content cache reused publication authority after epoch revocation")
