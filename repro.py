import tempfile

from tufrole.canonical import sign
from tufrole.roles import Role
from tufrole.service import RoleService


with tempfile.TemporaryDirectory() as tmp:
    service = RoleService(tmp)
    signature = sign("root", 2, 1, "root-one", envelope=1)
    tx = service.begin(Role("root", 2, 1, signature))
    service.rotate(2, {"root": "root-two"}, {"root"})
    snapshot = service.recover(tx)
    assert snapshot == {"format": 1, "roles": {"root": {"version": 2}}}
    print("OK: prepared transaction retained its epoch-1 signing context after rotation")
