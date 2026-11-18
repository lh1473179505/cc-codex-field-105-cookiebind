def delivery_view(broker):
    return {"rows": list(broker.sink.rows), "done": sorted(broker.spool.done),
            "epoch": broker.access.epoch}
