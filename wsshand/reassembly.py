class Reassembly:
    def __init__(self):
        self.parts = {}
        self.completed = set()

    def accept(self, fragment):
        key = (fragment.session, fragment.message)
        if key in self.completed:
            return None
        self.parts.setdefault(key, {})[fragment.index] = fragment
        if not fragment.final:
            return None
        pieces = self.parts.pop(key)
        self.completed.add(key)
        return "".join(pieces[i].text for i in sorted(pieces))

    def capture(self):
        return {"completed": sorted(self.completed),
                "parts": {"|".join(k): {str(i): f for i, f in v.items()}
                          for k, v in self.parts.items()}}

    def restore(self, state):
        self.completed = {tuple(v) for v in state["completed"]}
        self.parts = {}
