from .inbox import Inbox
from .index import FindingIndex, TriageStore
from .ruleset import RuleSet

class Pipeline:
    def __init__(self, fail=()):
        self.rules = RuleSet()
        self.inbox = Inbox()
        self.index = FindingIndex(fail)

    def submit(self, findings):
        token = self.inbox.stage(findings, self.rules)
        try:
            return self.inbox.materialize(token, self.index)
        except IOError:
            self.inbox.pending.pop(token, None)
            raise

    def begin(self, findings):
        return self.inbox.stage(findings, self.rules)

    def commit(self, token):
        return self.inbox.materialize(token, self.index)

    def snapshot(self):
        return TriageStore().capture(self.inbox, self.rules)

    def restore(self, state):
        self.inbox, self.rules = TriageStore().load(state)
