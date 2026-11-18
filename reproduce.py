from sarifgate.model import Finding
from sarifgate.pipeline import Pipeline
from sarifgate.report import board

def scenario():
    pipe = Pipeline(fail={"dead"})
    token = pipe.begin([
        Finding("f1", "CWE-79", "error", 1, "abc"),
        Finding("f2", "CWE-89", "error", 1, "dead"),
    ])
    pipe.rules.revoke("CWE-79")
    try:
        pipe.commit(token)
    except IOError:
        pass
    snap = pipe.snapshot()
    pipe.restore(snap)
    return board(pipe)

if __name__ == "__main__":
    got = scenario()
    assert got["findings"] == [("CWE-79", "error")]
    assert "f1" in got["published"] and "f2" in got["published"]
    assert "CWE-79" in got["quarantine"]
    print("reproduced: quarantined rule still indexed; failed finding marked published", got)
