class TrustPolicy:
    def __init__(self):
        self.epoch = 1
        self.roles = {"builder", "promoter"}
        self.revoked_roles = set()

    def allow(self, artifact):
        return (
            artifact.role in self.roles
            and artifact.role not in self.revoked_roles
            and artifact.epoch >= self.epoch
        )

    def revoke_role(self, role):
        self.revoked_roles.add(role)
        self.epoch += 1
