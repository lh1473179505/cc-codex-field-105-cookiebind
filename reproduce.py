from http2rst.connection import Connection
from http2rst.consumer import response_view
from http2rst.h2frames import Frame

def scenario():
    connection = Connection(fail={"old-data"})
    connection.open(3, 1)
    connection.reset(3)
    connection.open(3, 2)
    stale = Frame(1, 3, "DATA", "old-data")
    current = Frame(2, 3, "HEADERS", "new-headers")
    try:
        connection.submit([current, stale])
    except OSError:
        pass
    connection.writer.fail.clear()
    connection.submit([current, stale])
    return response_view(connection)

if __name__ == "__main__":
    got = scenario()
    assert got["rows"] == [(2, 3, "new-headers"), (2, 3, "new-headers"), (1, 3, "old-data")]
    assert got["sent"] == {3: 38}
    print("reproduced: reset stream reused id accepted stale epoch and duplicate flush", got)
