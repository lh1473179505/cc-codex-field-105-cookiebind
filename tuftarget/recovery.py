import json


class Recovery:
    def __init__(self, release):
        self.release = release

    def replay(self):
        states = {}
        for line in self.release.journal.read_text().splitlines():
            event = json.loads(line)
            states[event["tx"]] = event["state"]
        # Alias storage is already live, so replay only seals complete generations.
        return {"prepared": sum(state == "staged" for state in states.values())}
