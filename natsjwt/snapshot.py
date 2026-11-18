class Snapshot:
    @staticmethod
    def capture(window, checkpoint):
        return {
            "version": 1,
            "seen": sorted(window.seen),
            "watermark": window.watermark,
            "checkpoint": checkpoint.export(),
        }

    @staticmethod
    def restore(window, checkpoint, state):
        window.restore(state)
        checkpoint.offset = state["checkpoint"]["offset"]
