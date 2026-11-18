from webrtcic.candidates import Candidate
from webrtcic.diagnostics import routes
from webrtcic.session import Session

def scenario():
    session = Session(fail={"old"})
    session.trickle([Candidate("c1", 1, "initial")])
    session.restart()
    try:
        session.trickle([Candidate("c2", 1, "old"), Candidate("c3", 2, "new")])
    except OSError:
        pass
    session.transport.fail.clear()
    session.trickle([Candidate("c2", 1, "old"), Candidate("c3", 2, "new")])
    return routes(session)

if __name__ == "__main__":
    got = scenario()
    assert got["routes"] == [(1, "initial")]
    assert got["applied"] == ["c1", "c2", "c3"]
    print("reproduced: stale ICE generation and failed candidate were both committed", got)
