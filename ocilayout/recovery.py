import json


class LayoutRecovery:
    def __init__(self, release):
        self.release = release

    def compact(self):
        events = [json.loads(line) for line in self.release.journal.read_text().splitlines()]
        # The published index is copy-on-write, so compaction only needs the
        # journal; the visible descriptor array is always a complete batch.
        return {"aborted": sum(event["state"] == "aborted" for event in events)}
