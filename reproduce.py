from natsjwt.audit import inspect
from natsjwt.events import Event
from natsjwt.service import Service

def scenario():
    service = Service(fail={"beta"})
    second = Event("b", 2, 2, "beta")
    first = Event("a", 1, 2, "alpha")
    try:
        service.ingest(second)
    except OSError:
        pass
    service.sink.fail.clear()
    service.ingest(first)
    service.ingest(second)
    return inspect(service)

if __name__ == "__main__":
    result = scenario()
    assert result["values"] == []
    assert result["offset"] == 2
    assert result["pending"] == []
    print("reproduced: barrier closed early and failed replay was forgotten", result)
