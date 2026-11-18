class Snapshot:
    def save(self, dispatcher, watermarks):
        return {"kind": "trigger-1", "handled": sorted(dispatcher.handled),
                "positions": dict(watermarks.positions)}

    def restore(self, state, dispatcher, watermarks):
        dispatcher.handled = set(state["handled"])
        watermarks.positions = dict(state["positions"])
