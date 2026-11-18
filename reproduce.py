from solaceacl.broker import Broker
from solaceacl.consumer import delivery_view
from solaceacl.domain import Message

def scenario():
    broker = Broker(fail={"bad"})
    staged = broker.begin([Message("old", 1, "queued")])
    broker.access.revoke(1)
    broker.commit(staged)
    try:
        broker.publish([Message("new", 2, "bad")])
    except RuntimeError:
        pass
    broker.sink.fail.clear()
    broker.publish([Message("new", 2, "bad")])
    return delivery_view(broker)

if __name__ == "__main__":
    got = scenario()
    assert got["rows"] == [(1, "queued")]
    assert got["done"] == ["new", "old"]
    print("reproduced: revoked staged message escaped and failed publish became done", got)
