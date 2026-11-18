from .fragments import parse_reference, seal
from .model import DocumentState, DocumentTransaction
from .xmlstore import Store


class Service:
    def __init__(self, workspace):
        self.store = Store(workspace)
        self.generation = 1
        self.keys = {1: b"xml-document-key-v1"}
        self.transactions = {}
        self.staged = []

    def load(self, identifier):
        tx = DocumentTransaction(identifier, self.generation, DocumentState.KEYED)
        self.transactions[identifier] = tx
        self.store.append("document_loaded", identifier=identifier, generation=self.generation)
        return tx

    def rotate(self, secret):
        self.generation += 1
        self.keys[self.generation] = secret
        self.store.append("xml_key_rotated", generation=self.generation)

    def encrypt_fragment(self, identifier, fragment):
        tx = self.transactions[identifier]
        reference, root = parse_reference(fragment)
        encoded = seal(self.keys[self.generation], self.generation, reference, root.text or "")
        tx.fragments[reference] = encoded
        tx.state = DocumentState.SEALED
        self.staged.append((identifier, reference))
        self.store.append("fragment_sealed", identifier=identifier, reference=reference, generation=self.generation)
        if len(tx.fragments) > 2:
            raise ValueError("fragment batch limit")
        return encoded

    def abort(self, identifier):
        self.transactions.pop(identifier, None)
        self.store.append("document_aborted", identifier=identifier)

    def audit(self):
        return {"staged": list(self.staged), "documents": sorted(self.transactions)}
