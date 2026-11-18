import json


class CacheRecovery:
    def __init__(self, exporter):
        self.exporter = exporter

    def collect(self):
        refs = self.exporter.refs.all()
        for layer, count in refs.items():
            if count <= 0:
                self.exporter.content.remove(layer)
        return dict(refs)
