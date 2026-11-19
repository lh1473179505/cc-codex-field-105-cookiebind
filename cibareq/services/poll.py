"""Online transaction entry points."""
from __future__ import annotations

from cibareq.domain.states import FINAL, STAGE_PHASES, WORK_KEY, new_session, require_phase
from cibareq.handoff.channel import Migration


class OnlineService:
    def __init__(self, store):
        self.store = store
        self.migration = Migration(store)

    def start_auth(self, session_id: str, subject: str, authority: str, artifact: str, channel: str) -> dict:
        if session_id in self.store.data["sessions"]:
            raise ValueError("session already exists")
        session = new_session(session_id, subject, authority, artifact, channel, self.store.epoch(authority))
        self.store.data["sessions"][session_id] = session
        self.store.append("open", session=session_id, subject=subject, authority=authority, artifact=artifact, channel=channel)
        self.store.save()
        return session

    def queue_decision(self, session_id: str, transaction_id: str, payload: dict) -> dict:
        session = self.store.data["sessions"][session_id]
        if session["epoch"] != self.store.epoch(session["authority"]):
            raise PermissionError("session authorization epoch is stale")
        require_phase(session, tuple(STAGE_PHASES))
        if transaction_id in self.store.data["transactions"]:
            raise ValueError("transaction already exists")
        transaction = {"id": transaction_id, "session": session_id, "epoch": session["epoch"], "status": "pending", "payload": dict(payload)}
        self.store.data["transactions"][transaction_id] = transaction
        session[WORK_KEY]["tx"] = transaction_id
        session[WORK_KEY]["payload"] = dict(payload)
        self.store.append("stage", session=session_id, transaction=transaction_id, payload=dict(payload))
        self.store.save()
        return transaction

    def move_poll(self, source_id: str, target_id: str, channel: str) -> dict:
        return self.migration.move_poll(source_id, target_id, channel)

    def redeem_auth(self, session_id: str, transaction_id: str | None = None) -> dict:
        session = self.store.data["sessions"][session_id]
        transaction_id = transaction_id or session[WORK_KEY]["tx"]
        transaction = self.store.data["transactions"][transaction_id]
        if transaction["session"] != session_id:
            raise PermissionError("transaction belongs to another session")
        if transaction["status"] != "pending":
            raise RuntimeError("transaction is not pending")
        transaction["status"] = "committed"
        session["phase"] = FINAL
        self.store.append("commit", session=session_id, transaction=transaction_id)
        self.store.save()
        return transaction

    def rotate_client_epoch(self, authority: str) -> int:
        epoch = self.store.epoch(authority) + 1
        self.store.data["epochs"][authority] = epoch
        self.store.append("revoke", authority=authority)
        self.store.save()
        return epoch
