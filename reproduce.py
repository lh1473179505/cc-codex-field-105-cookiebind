from snsdeliv.messages import Notice
from snsdeliv.report import view
from snsdeliv.subscriptions import Subscriber
from snsdeliv.worker import Worker

def scenario():
    worker = Worker()
    worker.subscribe(Subscriber("a"))
    worker.subscribe(Subscriber("b", fail={"two"}))
    notices = [Notice("n2", 2, "two"), Notice("n1", 1, "one")]
    try:
        worker.publish(notices)
    except OSError:
        pass
    worker.registry.subscribers["b"].fail.clear()
    worker.publish(notices)
    return view(worker)

if __name__ == "__main__":
    got = scenario()
    assert got["rows"] == {"a": ["one", "two"], "b": ["one"]}
    assert got["done"] == ["n1", "n2"]
    print("reproduced: shared fan-out ledger stranded subscriber b", got)
