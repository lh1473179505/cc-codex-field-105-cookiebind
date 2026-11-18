class RuleSet:
    def __init__(self):
        self.epoch = 1
        self.active = {"CWE-79", "CWE-89"}
        self.quarantine = set()

    def accept(self, finding):
        return (
            finding.rule in self.active
            and finding.rule not in self.quarantine
            and finding.epoch >= self.epoch
        )

    def revoke(self, rule):
        self.quarantine.add(rule)
        self.epoch += 1
