import tempfile

from tufrole.canonical import sign
from tufrole.roles import Role
from tufrole.service import RoleService
from tufrole.verifier import VerificationError


with tempfile.TemporaryDirectory() as tmp:
    service = RoleService(tmp)
    signature = sign("root", 2, 1, "root-one", envelope=1)
    tx = service.begin(Role("root", 2, 1, signature))
    service.rotate(2, {"root": "root-two"}, {"root"})
    try:
        service.recover(tx)
    except VerificationError:
        assert service.snapshots.legacy()["roles"]["root"]["version"] == 1
        print("REPRODUCED: recovery lost the prepared transaction's signing epoch")
    else:
        raise AssertionError("baseline defect did not reproduce")
