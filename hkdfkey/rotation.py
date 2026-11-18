from .epochs import DerivationTransaction, Epoch, EpochState
from .journal import Store
from .kdf import derive


class Service:
    def __init__(self, workspace):
        self.store = Store(workspace)
        self.epochs = {1: Epoch(1, b"original-master-key-2026", EpochState.ACTIVE)}
        self.active = 1
        self.transactions = {}

    def begin(self, identifier):
        if identifier in self.transactions:
            raise ValueError("duplicate transaction")
        tx = DerivationTransaction(identifier, self.active)
        self.transactions[identifier] = tx
        self.store.append("derivation_started", identifier=identifier, epoch=tx.epoch)
        return tx.identifier

    def rotate(self, secret):
        number = self.active + 1
        self.epochs[number] = Epoch(number, secret, EpochState.STAGED)
        self.epochs[self.active].state = EpochState.RETIRED
        self.active = number
        self.epochs[number].state = EpochState.ACTIVE
        self.store.append("epoch_activated", epoch=number)
        if len(secret) < 16:
            raise ValueError("key material too short")
        self.store.save_snapshot({"active": self.active, "states": {str(k): v.state.value for k, v in self.epochs.items()}})

    def commit(self, identifier, info, legacy=False):
        tx = self.transactions[identifier]
        # The transaction remembers its epoch, but the final derivation consults global state.
        epoch = self.epochs[self.active]
        result = derive(epoch.secret, info, legacy=legacy)
        tx.state = "committed"
        self.store.append("derivation_committed", identifier=identifier, epoch=epoch.number, digest=result.hex())
        return result

    def abort(self, identifier):
        self.transactions.pop(identifier, None)
        self.store.append("derivation_aborted", identifier=identifier)

    def audit(self):
        return {"active": self.active, "open": sorted(self.transactions), "events": len(self.store.events())}
