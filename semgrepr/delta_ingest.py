"""Incremental writer with revocation, restoration and ordering."""
from __future__ import annotations

from .shard_records import Record, State
from .shard_journal import OperationJournal
from .rule_cache import FingerprintIndex
from .shard_state import advance


def apply_delta(state: State, index: FingerprintIndex, journal: OperationJournal, *, action: str,
                key: str, scope: str, fingerprint: str, value: str, sequence: int) -> dict[str, object]:
    if action not in {"delta", "revoke", "restore"}:
        raise ValueError("unknown delta action")
    identity = scope + ":" + key
    if sequence <= state.high_water:
        return {"accepted": False, "reason": "stale"}
    journal.append(action, sequence, max(1, state.generation), {"key": key, "scope": scope, "value": value})
    state.high_water = max(state.high_water, sequence)
    if action == "revoke":
        state.revoked[identity] = sequence
        state.records.pop(identity, None)
        state.phase = advance(state.phase, "revoke")
    else:
        record = Record(key, scope, fingerprint, value, state.generation, sequence)
        state.records[identity] = record
        state.revoked.pop(identity, None)
        index.put(record)
        state.phase = advance(state.phase, action)
    state.history.append("%s:%s:%d" % (action, identity, sequence))
    return {"accepted": True, "identity": identity, "sequence": sequence}
