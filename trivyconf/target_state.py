"""Explicit lifecycle transitions for the two write paths."""
from __future__ import annotations


PHASES = ('UNBOUND', 'MANIFESTED', 'POLICY_FLOW', 'SUSPENDED', 'REBOUND')
TRANSITIONS = {'UNBOUND': {'snapshot': 'MANIFESTED'}, 'MANIFESTED': {'delta': 'POLICY_FLOW', 'revoke': 'SUSPENDED', 'snapshot': 'MANIFESTED'}, 'POLICY_FLOW': {'delta': 'POLICY_FLOW', 'revoke': 'SUSPENDED', 'snapshot': 'REBOUND', 'restore': 'REBOUND'}, 'SUSPENDED': {'snapshot': 'REBOUND', 'restore': 'REBOUND', 'delta': 'POLICY_FLOW', 'revoke': 'SUSPENDED'}, 'REBOUND': {'delta': 'POLICY_FLOW', 'revoke': 'SUSPENDED', 'snapshot': 'REBOUND', 'restore': 'REBOUND'}}


def advance(current: str, action: str) -> str:
    try:
        return TRANSITIONS[current][action]
    except KeyError as exc:
        raise ValueError("illegal lifecycle transition: %s + %s" % (current, action)) from exc
