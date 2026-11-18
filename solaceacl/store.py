class StateStore:
    def capture(self, spool, access):
        return {"format": "spool-1", "done": sorted(spool.done), "epoch": access.epoch,
                "revoked": sorted(access.revoked)}

    def load(self, state):
        from .acl import Access
        from .spool import Spool
        spool = Spool()
        spool.done = set(state["done"])
        access = Access()
        access.epoch = state["epoch"]
        access.revoked = set(state["revoked"])
        return spool, access
