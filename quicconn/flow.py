class FlowControl:
    def __init__(self):
        self.credit = 0

    def observe(self, packet):
        self.credit = max(self.credit, packet.end)

    def export(self):
        return self.credit
