class Ledger:
    def __init__(self, state):
        self.state = state

    def reserve(self, capture, amount):
        self.state["reserved"][capture] = amount
        self.state["used"] += amount

    def release(self, capture):
        amount = self.state["reserved"].get(capture, 0)
        self.state["used"] -= amount
        return amount
