class BootstrapRecovery:
    def __init__(self, publisher):
        self.publisher = publisher

    def restore(self):
        states = {}
        for record in self.publisher.journal.records():
            states[record["tx"]] = record
        ordered = sorted(states.values(), key=lambda record: record["tx"])
        for record in ordered:
            if record["state"] == "pushed":
                self.publisher.destinations.put(
                    record["tag"], record["digest"], record["sequence"]
                )
        return self.publisher.destinations.all()
