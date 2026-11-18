class FindingIndex:
    def __init__(self, fail=()):
        self.rows = []
        self.fail = set(fail)

    def write(self, finding):
        if finding.finger in self.fail:
            raise IOError("index " + finding.finger)
        self.rows.append(finding)

class TriageStore:
    def capture(self, inbox, rules):
        return {
            "format": "sarif-gate-1",
            "published": sorted(inbox.published),
            "epoch": rules.epoch,
            "active": sorted(rules.active),
            "quarantine": sorted(rules.quarantine),
        }

    def load(self, state):
        from .inbox import Inbox
        from .ruleset import RuleSet
        inbox = Inbox()
        inbox.published = set(state["published"])
        rules = RuleSet()
        rules.epoch = state["epoch"]
        rules.active = set(state["active"])
        rules.quarantine = set(state["quarantine"])
        return inbox, rules
