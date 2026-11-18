"""Explicit lifecycle transitions for the two write paths."""
from __future__ import annotations


PHASES = ('DRAFT', 'CONTEXT_READY', 'ACTIVE', 'SUSPENDED', 'RESUMED', 'CLOSED')
TRANSITIONS = {'DRAFT': {'snapshot': 'CONTEXT_READY'}, 'CONTEXT_READY': {'delta': 'ACTIVE', 'revoke': 'SUSPENDED', 'snapshot': 'CONTEXT_READY', 'restore': 'CLOSED'}, 'ACTIVE': {'delta': 'ACTIVE', 'revoke': 'SUSPENDED', 'snapshot': 'RESUMED', 'restore': 'CLOSED'}, 'SUSPENDED': {'snapshot': 'RESUMED', 'restore': 'CLOSED', 'delta': 'ACTIVE', 'revoke': 'SUSPENDED'}, 'RESUMED': {'delta': 'ACTIVE', 'revoke': 'SUSPENDED', 'snapshot': 'RESUMED', 'restore': 'CLOSED'}, 'CLOSED': {'delta': 'ACTIVE', 'revoke': 'SUSPENDED', 'snapshot': 'RESUMED', 'restore': 'CLOSED'}}


def advance(current: str, action: str) -> str:
    try:
        return TRANSITIONS[current][action]
    except KeyError as exc:
        raise ValueError("illegal lifecycle transition: %s + %s" % (current, action)) from exc
