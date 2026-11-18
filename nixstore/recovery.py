import json


class StoreRecovery:
    def __init__(self, release):
        self.release = release

    def reconcile(self):
        # Database registrations are treated as durable authorities.
        return {
            "registered": len(self.release.db.all()),
            "last": json.loads(self.release.journal.read_text().splitlines()[-1])["state"],
        }
