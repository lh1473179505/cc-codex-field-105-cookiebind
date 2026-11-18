def session_view(endpoint):
    return {"messages": list(endpoint.socket.messages),
            "epochs": dict(endpoint.handshakes.epochs),
            "completed": sorted(endpoint.reassembly.completed)}
