"""Explicit lifecycle transitions for the two write paths."""
from __future__ import annotations


PHASES = ('UNTRACKED', 'CATALOGUED', 'ASSIGNING', 'REVOKED', 'REASSIGNED')
TRANSITIONS = {'UNTRACKED': {'snapshot': 'CATALOGUED'}, 'CATALOGUED': {'delta': 'ASSIGNING', 'revoke': 'REVOKED', 'snapshot': 'CATALOGUED'}, 'ASSIGNING': {'delta': 'ASSIGNING', 'revoke': 'REVOKED', 'snapshot': 'REASSIGNED', 'restore': 'REASSIGNED'}, 'REVOKED': {'snapshot': 'REASSIGNED', 'restore': 'REASSIGNED', 'delta': 'ASSIGNING', 'revoke': 'REVOKED'}, 'REASSIGNED': {'delta': 'ASSIGNING', 'revoke': 'REVOKED', 'snapshot': 'REASSIGNED', 'restore': 'REASSIGNED'}}


def advance(current: str, action: str) -> str:
    try:
        return TRANSITIONS[current][action]
    except KeyError as exc:
        raise ValueError("illegal lifecycle transition: %s + %s" % (current, action)) from exc
