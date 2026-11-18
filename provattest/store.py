class SealStore:
    def __init__(self, fail=()):
        self.items = []
        self.fail = set(fail)

    def put(self, artifact):
        if artifact.digest in self.fail:
            raise RuntimeError("seal " + artifact.digest)
        self.items.append(artifact)

class Checkpoint:
    def capture(self, attestor, policy):
        return {
            "format": "prov-1",
            "granted": sorted(attestor.granted),
            "epoch": policy.epoch,
            "roles": sorted(policy.roles),
            "revoked_roles": sorted(policy.revoked_roles),
        }

    def load(self, state):
        from .attestor import Attestor
        from .policy import TrustPolicy
        attestor = Attestor()
        attestor.granted = set(state["granted"])
        policy = TrustPolicy()
        policy.epoch = state["epoch"]
        policy.roles = set(state["roles"])
        policy.revoked_roles = set(state["revoked_roles"])
        return attestor, policy
