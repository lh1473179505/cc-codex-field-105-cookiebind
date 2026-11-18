class Journal:
    def __init__(self):
        self.entries = []

    def record(self, candidate):
        self.entries.append(candidate.key)

    def export(self):
        return {"format": "ice-journal-1", "entries": list(self.entries)}
