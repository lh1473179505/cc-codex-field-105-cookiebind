from .ledger import Ledger

class Archive:
    @staticmethod
    def save(ledger):
        state = ledger.export()
        state["format"] = "fanout-v1"
        return state

    @staticmethod
    def open(state):
        ledger = Ledger()
        ledger.done = set(state["done"])
        ledger.highwater = state["highwater"]
        return ledger
