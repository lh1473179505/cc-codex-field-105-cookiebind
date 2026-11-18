from provattest.artifact import Artifact
from provattest.service import Service
from provattest.verify import bundle_view

def scenario():
    svc = Service(fail={"d2"})
    token = svc.begin([
        Artifact("p1", "d1", "builder", 1),
        Artifact("p2", "d2", "promoter", 1),
    ])
    svc.policy.revoke_role("builder")
    try:
        svc.commit(token)
    except RuntimeError:
        pass
    snap = svc.snapshot()
    svc.restore(snap)
    return bundle_view(svc)

if __name__ == "__main__":
    got = scenario()
    assert got["sealed"] == [("builder", "d1")]
    assert "p1" in got["granted"] and "p2" in got["granted"]
    assert "builder" in got["revoked"]
    print("reproduced: revoked builder still sealed; failed digest remains granted", got)
