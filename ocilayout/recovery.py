import json


class LayoutRecovery:
    def __init__(self, release):
        self.release = release

    def compact(self):
        events = [json.loads(line) for line in self.release.journal.read_text().splitlines()]
        # Compaction trusts the shared index left by the staging path.
        return {"aborted": sum(event["state"] == "aborted" for event in events)}
