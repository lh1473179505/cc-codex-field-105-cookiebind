class LegacyResolver:
    def __init__(self, publisher):
        self.publisher = publisher

    def resolve(self, tag):
        value = self.publisher.destinations.all()[tag]
        return "dir://sha256:" + value["digest"]

    def snapshot(self):
        return {
            tag: value["digest"]
            for tag, value in sorted(self.publisher.destinations.all().items())
        }
