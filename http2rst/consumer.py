def response_view(connection):
    return {"rows": list(connection.writer.rows), "sent": dict(connection.windows.sent),
            "states": dict(connection.table.states)}
