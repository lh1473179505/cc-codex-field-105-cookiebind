from caplease.handover import Handover
from caplease.lifecycle import FINAL, STAGE_PHASES, new_session, require_phase


class Service:
    def __init__(self, store):
        self.store = store
        self.handover = Handover(store)

    def prepare(self, session_id, subject, authority, artifact, channel):
        if session_id in self.store.data["sessions"]:
            raise ValueError("session already exists")
        cursor_id = session_id
        self.store.data["cursors"][cursor_id] = []
        session = new_session(
            session_id, subject, authority, artifact, channel, self.store.epoch(authority), cursor_id
        )
        self.store.data["sessions"][session_id] = session
        self.store.append(
            "open", session=session_id, subject=subject, authority=authority, artifact=artifact, channel=channel
        )
        self.store.save()
        return session

    def stage(self, session_id, transaction_id, payload):
        session = self.store.data["sessions"][session_id]
        if session["epoch"] != self.store.epoch(session["authority"]):
            raise PermissionError("session authorization epoch is stale")
        require_phase(session, STAGE_PHASES)
        if transaction_id in self.store.data["transactions"]:
            raise ValueError("transaction already exists")
        transaction = {
            "id": transaction_id,
            "session": session_id,
            "epoch": session["epoch"],
            "status": "pending",
            "payload": dict(payload),
        }
        self.store.data["transactions"][transaction_id] = transaction
        session["work"]["tx"] = transaction_id
        session["work"]["payload"] = dict(payload)
        marks = self.store.data["cursors"][session["cursor_id"]]
        marks.extend(list(payload["marks"]))
        self.store.append("stage", session=session_id, transaction=transaction_id, payload=dict(payload))
        self.store.save()
        return transaction

    def move(self, source_id, target_id, channel):
        return self.handover.move(source_id, target_id, channel)

    def commit(self, session_id, transaction_id=None):
        session = self.store.data["sessions"][session_id]
        transaction_id = transaction_id or session["work"]["tx"]
        transaction = self.store.data["transactions"][transaction_id]
        if transaction["session"] != session_id:
            raise PermissionError("transaction belongs to another session")
        if transaction["epoch"] != session["epoch"]:
            raise PermissionError("transaction epoch does not match pinned session epoch")
        if transaction["status"] != "pending":
            raise RuntimeError("transaction is not pending")
        transaction["status"] = "committed"
        session["phase"] = FINAL
        self.store.append("commit", session=session_id, transaction=transaction_id)
        self.store.save()
        return transaction

    def revoke(self, authority):
        epoch = self.store.epoch(authority) + 1
        self.store.data["epochs"][authority] = epoch
        self.store.append("revoke", authority=authority)
        self.store.save()
        return epoch
