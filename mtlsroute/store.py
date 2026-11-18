class Snapshot:
    def capture(self, ledger, trust):
        return {
            "format": "mtls-1",
            "accepted": sorted(ledger.accepted),
            "epoch": trust.epoch,
            "revoked": sorted(trust.revoked),
            "allowed": sorted(trust.allowed),
        }

    def load(self, state):
        from .session import SessionLedger
        from .trust import PeerTrust
        ledger = SessionLedger()
        ledger.accepted = set(state["accepted"])
        trust = PeerTrust()
        trust.epoch = state["epoch"]
        trust.revoked = set(state["revoked"])
        trust.allowed = set(state["allowed"])
        return ledger, trust
