"""Explicit lifecycle transitions for the two write paths."""
from __future__ import annotations


PHASES = ('IDLE', 'SWEPT', 'SHARDING', 'FENCED', 'RESUMED')
TRANSITIONS = {'IDLE': {'snapshot': 'SWEPT', 'delta': 'SHARDING'}, 'SWEPT': {'delta': 'SHARDING', 'revoke': 'FENCED', 'snapshot': 'SWEPT'}, 'SHARDING': {'delta': 'SHARDING', 'revoke': 'FENCED', 'snapshot': 'RESUMED', 'restore': 'RESUMED'}, 'FENCED': {'snapshot': 'RESUMED', 'restore': 'RESUMED', 'delta': 'SHARDING', 'revoke': 'FENCED'}, 'RESUMED': {'delta': 'SHARDING', 'revoke': 'FENCED', 'snapshot': 'RESUMED', 'restore': 'RESUMED'}}


def advance(current: str, action: str) -> str:
    try:
        return TRANSITIONS[current][action]
    except KeyError as exc:
        raise ValueError("illegal lifecycle transition: %s + %s" % (current, action)) from exc
