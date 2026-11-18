"""Authoritative full-snapshot importer and convergence boundary."""
from __future__ import annotations

from .shard_records import Record, State
from .shard_journal import OperationJournal
from .rule_cache import FingerprintIndex
from .shard_state import advance


def merge_snapshot(state: State, index: FingerprintIndex, journal: OperationJournal, *, generation: int,
                   sequence: int, rows: list[dict[str, object]]) -> dict[str, object]:
    if generation < state.generation or (generation == state.generation and sequence <= state.high_water):
        return {"accepted": False, "reason": "stale-snapshot"}
    journal.append("snapshot", sequence, generation, {"rows": rows})
    records: dict[str, Record] = {}
    for row in rows:
        key = str(row["key"])
        scope = str(row.get("scope", "main"))
        fingerprint = str(row["fingerprint"])
        value = str(row["value"])
        record = Record(key, scope, fingerprint, value, generation, sequence)
        
        records[record.identity] = record
        index.put(record)
    state.records = records
    state.revoked = {
        identity: revoked_sequence
        for identity, revoked_sequence in state.revoked.items()
        if identity not in records
    }
    state.generation = generation
    state.high_water = max(state.high_water, sequence)
    state.phase = advance(state.phase, "snapshot")
    state.history.append("snapshot:%d:%d" % (generation, sequence))
    return {"accepted": True, "generation": generation, "sequence": sequence, "count": len(records)}
