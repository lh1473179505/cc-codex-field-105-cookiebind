from sqsqueue.api import Queue
from sqsqueue.consumer import inspect
from sqsqueue.queue_model import Item

def scenario():
    queue = Queue(fail={"bad"})
    queue.enqueue(Item("a", "ok"))
    queue.enqueue(Item("b", "bad"))
    queue.receive()
    try:
        queue.acknowledge(["a", "b"])
    except OSError:
        pass
    state = queue.storage.export()
    restored = Queue()
    restored.restore(state)
    restored.visibility.tick(10)
    restored.receive()
    return inspect(queue), inspect(restored)

if __name__ == "__main__":
    original, restored = scenario()
    assert original["states"] == {"a": "acked", "b": "acked"}
    assert original["remote"] == ["ok"]
    assert restored["states"] == original["states"]
    print("reproduced: partial batch acknowledgement became permanent", original)
