import tempfile
from pathlib import Path

from rekorlog.audit import LegacyAudit
from rekorlog.entries import sign
from rekorlog.service import LogService, ReleaseError


with tempfile.TemporaryDirectory() as tmp:
    service = LogService(Path(tmp), {"publisher": "secret"})
    first = sign("sha256:aaa", "publisher", "secret")
    bad = sign("sha256:bbb", "publisher", "secret")
    bad.signature = "0" * 64
    try:
        service.append([first, bad])
    except ReleaseError:
        pass
    else:
        raise AssertionError("invalid batch was accepted")
    allocated = service.append([sign("sha256:ccc", "publisher", "secret")])
    assert allocated[0]["index"] == 2, allocated
    service.recover()
    try:
        LegacyAudit(service).export()
    except ValueError as error:
        assert "0,1" in str(error)
        print("REPRODUCED: aborted allocations became legacy checkpoint gaps")
    else:
        raise AssertionError("baseline defect did not reproduce")
