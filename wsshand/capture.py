class Capture:
    VERSION = "ws-capture-1"

    def save(self, reassembly, handshakes):
        return {"version": self.VERSION, "epochs": dict(handshakes.epochs),
                "reassembly": reassembly.capture()}

    def load(self, state, reassembly, handshakes):
        handshakes.epochs = dict(state["epochs"])
        reassembly.restore(state["reassembly"])
