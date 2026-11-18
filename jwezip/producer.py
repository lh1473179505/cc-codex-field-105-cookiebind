from .compression import authentication, compress, protected_header
from .jwestore import Store
from .model import TokenState, TokenTransaction


class Service:
    def __init__(self, workspace):
        self.store = Store(workspace)
        self.generation = 1
        self.keys = {1: b"jwe-content-key-v1"}
        self.transactions = {}
        self.buffers = {}

    def issue(self, identifier):
        self.transactions[identifier] = TokenTransaction(identifier, self.generation)
        self.buffers.setdefault(identifier, [])
        self.store.append("token_issued", identifier=identifier, generation=self.generation)

    def append(self, identifier, chunk):
        self.buffers[identifier].append(chunk)
        self.transactions[identifier].state = TokenState.BUFFERED

    def rotate(self, secret):
        self.generation += 1
        self.keys[self.generation] = secret
        self.store.append("jwe_key_rotated", generation=self.generation)

    def seal(self, identifier):
        body = compress(self.buffers[identifier])
        header = protected_header(self.generation, compressed=True)
        tag = authentication(self.keys[self.generation], header, body)
        self.transactions[identifier].state = TokenState.SEALED
        self.store.append("token_sealed", identifier=identifier, generation=self.generation, tag=tag)
        return {"protected": header, "ciphertext": body.hex(), "tag": tag}

    def abort(self, identifier):
        self.transactions.pop(identifier, None)
        self.store.append("token_aborted", identifier=identifier)

    def audit(self):
        return {"buffered_bytes": {k: sum(map(len, v)) for k, v in self.buffers.items()}}
