class Ledger:
    def __init__(self, state):
        self.state = state

    def reserve(self, capture, amount):
        self.state["reserved"][capture] = amount
        self.state["used"] += amount

    def release(self, capture):
        # Removing the reservation makes release idempotent: a capture can
        # only release its quota once, so ``used`` never goes negative even
        # when failure handling and recovery re-enter for the same capture.
        amount = self.state["reserved"].pop(capture, 0)
        self.state["used"] -= amount
        return amount
