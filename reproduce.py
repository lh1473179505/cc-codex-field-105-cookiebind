from mtlsroute.audit import route_view
from mtlsroute.peers import Frame
from mtlsroute.router import Router

def scenario():
    router = Router(fail={"poison"})
    token = router.open([Frame("s1", "edge-a", 1, "hello")])
    router.trust.rotate("edge-a", 2)
    router.finish(token)
    try:
        router.send([Frame("s2", "edge-b", 2, "poison")])
    except OSError:
        pass
    router.wire.fail.clear()
    snap = router.snapshot()
    router.restore(snap)
    # same key cannot retry while accepted is sticky after failed send
    wrote = router.send([Frame("s2", "edge-b", 2, "retry")])
    return route_view(router), wrote

if __name__ == "__main__":
    view, wrote = scenario()
    assert view["wire"] == [("edge-a", 1, "hello")]
    assert "s1" in view["accepted"] and "s2" in view["accepted"]
    assert wrote == 0
    print("reproduced: rotated epoch still committed; failed send stuck in accepted", view, wrote)
