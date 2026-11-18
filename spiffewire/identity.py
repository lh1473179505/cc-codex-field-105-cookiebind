class Bundle:
    def __init__(self):
        self.trust_domain = "prod.example"
        self.ids = {"spiffe://prod.example/api", "spiffe://prod.example/worker"}
        self.generation = 1

    def allows(self, spiffe_id, generation):
        return (
            spiffe_id in self.ids
            and spiffe_id.startswith("spiffe://" + self.trust_domain + "/")
            and generation >= self.generation
        )

    def migrate(self, new_domain, keep_ids):
        self.trust_domain = new_domain
        self.ids = set(keep_ids)
        self.generation += 1
