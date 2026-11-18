def view(worker):
    return {"rows": {s.name: list(s.rows) for s in worker.registry.ordered()},
            "done": sorted(worker.ledger.done), "highwater": worker.ledger.highwater}
