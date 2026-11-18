import tempfile

from nixstore.bundle import LegacyBundle
from nixstore.recovery import StoreRecovery
from nixstore.release import StoreRelease, StoreError


with tempfile.TemporaryDirectory() as tmp:
    release = StoreRelease(tmp)
    values = [{"name": "app", "value": 1}, {"name": "bad", "value": 2}]
    good_name, _ = release.nar.add(values[0])
    try:
        release.publish(values, {"app": release.signer.signature(good_name, 1)}, 1)
    except StoreError:
        pass
    StoreRecovery(release).reconcile()
    try:
        LegacyBundle(release).export()
    except RuntimeError as error:
        assert good_name in str(error)
        print("REPRODUCED: rollback left a registered path without store content")
    else:
        raise AssertionError("baseline defect did not reproduce")
