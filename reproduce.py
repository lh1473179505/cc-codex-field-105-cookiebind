from quicconn.connection import Connection
from quicconn.consumer import view
from quicconn.packets import Packet

def scenario():
    connection = Connection(fail={b"abcd"})
    connection.receive(Packet(7, 2, b"cd", True))
    try:
        connection.receive(Packet(7, 0, b"ab"))
    except OSError:
        pass
    state = connection.snapshot()
    migrated = Connection()
    migrated.migrate(state)
    migrated.receive(Packet(7, 0, b"ab"))
    return view(connection), view(migrated)

if __name__ == "__main__":
    original, migrated = scenario()
    assert original["payloads"] == []
    assert original["delivered"] == {7: 4}
    assert original["credit"] == 4
    assert migrated["payloads"] == []
    print("reproduced: byte stream committed offset before peer write and recovery", original)
