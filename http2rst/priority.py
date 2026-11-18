class PriorityTree:
    def __init__(self):
        self.parents = {}

    def depend(self, stream, parent=0):
        self.parents[stream] = parent

    def capture(self):
        return dict(self.parents)
