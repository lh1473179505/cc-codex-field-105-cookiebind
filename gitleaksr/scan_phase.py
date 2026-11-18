"""Explicit lifecycle transitions for the two write paths."""
from __future__ import annotations


PHASES = ('NEW', 'TREE_READY', 'COMMIT_FLOW', 'REDACTED', 'TREE_RESTORED')
TRANSITIONS = {'NEW': {'snapshot': 'TREE_READY'}, 'TREE_READY': {'delta': 'COMMIT_FLOW', 'revoke': 'REDACTED', 'snapshot': 'TREE_READY'}, 'COMMIT_FLOW': {'delta': 'COMMIT_FLOW', 'revoke': 'REDACTED', 'snapshot': 'TREE_RESTORED', 'restore': 'TREE_RESTORED'}, 'REDACTED': {'snapshot': 'TREE_RESTORED', 'restore': 'TREE_RESTORED', 'delta': 'COMMIT_FLOW', 'revoke': 'REDACTED'}, 'TREE_RESTORED': {'delta': 'COMMIT_FLOW', 'revoke': 'REDACTED', 'snapshot': 'TREE_RESTORED', 'restore': 'TREE_RESTORED'}}


def advance(current: str, action: str) -> str:
    try:
        return TRANSITIONS[current][action]
    except KeyError as exc:
        raise ValueError("illegal lifecycle transition: %s + %s" % (current, action)) from exc
