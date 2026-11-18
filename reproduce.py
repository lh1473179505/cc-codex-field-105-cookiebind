from wsshand.diagnostics import session_view
from wsshand.endpoint import Endpoint
from wsshand.frames import Fragment

def scenario():
    endpoint = Endpoint(fail={"AB"})
    endpoint.open("s")
    first = Fragment("s", 1, "m", 0, False, "A")
    last = Fragment("s", 1, "m", 1, True, "B")
    endpoint.receive(first)
    endpoint.migrate("s")
    try:
        endpoint.receive(last)
    except OSError:
        pass
    endpoint.socket.fail.clear()
    endpoint.receive(last)
    snapshot = endpoint.snapshot()
    restored = Endpoint()
    restored.restore(snapshot)
    return session_view(endpoint), session_view(restored)

if __name__ == "__main__":
    original, restored = scenario()
    assert original["messages"] == []
    assert original["completed"] == [("s", "m")]
    assert restored["epochs"] == {"s": 2}
    print("reproduced: old fragment completed after migration and retry was suppressed", original)
