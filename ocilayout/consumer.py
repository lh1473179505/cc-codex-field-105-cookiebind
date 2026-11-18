class LegacyLayout:
    def __init__(self, release):
        self.release = release

    def descriptor(self, os_name, architecture, variant=""):
        for item in self.release.index.read()["manifests"]:
            platform = item.get("platform", {})
            if (platform.get("os"), platform.get("architecture"), platform.get("variant", "")) == (os_name, architecture, variant):
                return {"digest": item["digest"], "size": item["size"]}
        raise KeyError(os_name + "/" + architecture)

    def platforms(self):
        return [
            item["platform"]["os"] + "/" + item["platform"]["architecture"]
            for item in self.release.index.read()["manifests"]
        ]
