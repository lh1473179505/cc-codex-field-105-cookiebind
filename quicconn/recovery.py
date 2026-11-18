class Recovery:
    def save(self, streams, flow):
        return {"format": "conn-1", "delivered": {str(k): s.delivered for k, s in streams.items()},
                "received": {str(k): sorted(s.received) for k, s in streams.items()},
                "credit": flow.export()}

    def load(self, state):
        from .streams import Stream
        streams = {}
        for key, delivered in state["delivered"].items():
            stream = Stream(int(key))
            stream.delivered = delivered
            stream.received = {tuple(v) for v in state["received"][key]}
            streams[int(key)] = stream
        return streams
