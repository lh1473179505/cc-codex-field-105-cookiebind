class Watches:
    def __init__(self):
        self.by_wd = {9: {"path": "/srv/old", "state": "stable", "epoch": 1}}
        self.paths = {"/srv/old": 9}

    def apply(self, event):
        if event["kind"] != "rename":
            return
        wd = event["wd"]
        old = self.by_wd[wd]["path"]
        self.paths.pop(old, None)
        self.by_wd[wd]["path"] = event["to"]
        self.by_wd[wd]["state"] = "moved"
        self.paths[event["to"]] = wd
