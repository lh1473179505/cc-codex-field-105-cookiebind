import tempfile

from tuftarget.client import LegacyTargetClient
from tuftarget.delegation import signature
from tuftarget.release import TargetRelease, DelegationError


with tempfile.TemporaryDirectory() as tmp:
    release = TargetRelease(tmp, {"targets": "secret"})
    target = {"role": "targets", "bytes": 1}
    # Calculate the digest through staging-compatible content encoding.
    from tuftarget.blobs import ContentStore
    probe = ContentStore(tmp + "/probe")
    digest = probe.add(target)
    items = [
        {"path": "app", "target": target, "role": "targets", "signature": signature("app", digest, "targets", "secret")},
        {"path": "agent", "target": {"role": "targets", "bytes": 2}, "role": "targets", "signature": "bad"},
    ]
    try:
        release.publish(items, 1)
    except DelegationError:
        pass
    else:
        raise AssertionError("invalid delegation was accepted")
    try:
        LegacyTargetClient(release).fetch("app")
    except RuntimeError as error:
        assert "escaped" in str(error)
        print("REPRODUCED: rollback left a staged target alias visible")
    else:
        raise AssertionError("baseline defect did not reproduce")
