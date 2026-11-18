from .hsmstore import Store
from .mechanisms import operate
from .model import Operation, TokenState


class Service:
    def __init__(self, workspace):
        self.store = Store(workspace)
        self.generation = 1
        self.keys = {1: {"pay-sign-01": b"hsm-pay-sign-key-v1", "ops-wrap-01": b"hsm-ops-wrap-key-v1"}}
        self.operations = {}
        self.handles = set()

    def login(self, slot):
        if slot != 7:
            raise ValueError("unknown slot")
        self.handles.add(slot)
        self.store.append("token_logged_in", slot=slot, generation=self.generation)

    def begin(self, identifier, key_label="pay-sign-01", slot=7):
        if slot not in self.handles:
            raise ValueError("login required")
        operation = Operation(identifier, slot, key_label, self.generation)
        self.operations[identifier] = operation
        self.store.append("operation_started", identifier=identifier, generation=self.generation, key_label=key_label)

    def rotate(self, keys):
        self.generation += 1
        self.keys[self.generation] = keys
        self.store.append("hsm_keys_rotated", generation=self.generation)

    def finish(self, identifier, payload, mechanism="ECDSA_SHA256", usage="sign"):
        operation = self.operations[identifier]
        operation.state = TokenState.COMMITTED
        try:
            result = operate(self.keys[self.generation][operation.key_label], mechanism, usage, payload)
        except ValueError:
            self.store.append("operation_committed", identifier=identifier, generation=self.generation, result="partial")
            raise
        self.store.append("operation_committed", identifier=identifier, generation=self.generation, result=result)
        return result

    def abort(self, identifier):
        operation = self.operations.pop(identifier)
        operation.state = TokenState.ABORTED
        self.store.append("operation_aborted", identifier=identifier)

    def logout(self, slot):
        self.handles.discard(slot)

    def audit(self):
        return {"handles": sorted(self.handles), "operations": sorted(self.operations)}
