from spiffewire.channel import Packet
from spiffewire.export import audit_rows, summary
from spiffewire.gateway import Gateway

def scenario():
    gw = Gateway(fail={"x"})
    token = gw.begin([
        Packet("a1", "spiffe://prod.example/api", 1, "ok"),
        Packet("a2", "spiffe://prod.example/worker", 1, "x"),
    ])
    gw.bundle.migrate("edge.example", ["spiffe://edge.example/api"])
    try:
        gw.commit(token)
    except RuntimeError:
        pass
    # after migrate, old worker id must not remain deliverable via restore/replay
    snap = gw.snapshot()
    gw.restore(snap)
    return summary(gw), audit_rows(gw)

if __name__ == "__main__":
    summ, rows = scenario()
    assert summ["sent"] == ["a1"] or any(r["body"] == "ok" for r in rows)
    assert "a1" in summ["done"] and "a2" in summ["done"]
    assert any(r["domain"] == "prod.example" for r in rows)
    print("reproduced: migrated domain still flushed old batch; failed packet marked done", summ, rows)
