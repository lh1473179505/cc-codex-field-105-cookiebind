def view(connection):
    return {"payloads": list(connection.peer.payloads),
            "delivered": {k: s.delivered for k, s in connection.streams.items()},
            "credit": connection.flow.credit}
