"""Explicit lifecycle transitions for the two write paths."""
from __future__ import annotations


PHASES = ('UNSCORED', 'PROFILED', 'RESCORING', 'VECTOR_REVOKED', 'PROFILE_RESTORED')
TRANSITIONS = {'UNSCORED': {'snapshot': 'PROFILED', 'restore': 'PROFILE_RESTORED'}, 'PROFILED': {'delta': 'RESCORING', 'revoke': 'VECTOR_REVOKED', 'snapshot': 'PROFILED'}, 'RESCORING': {'delta': 'RESCORING', 'revoke': 'VECTOR_REVOKED', 'snapshot': 'PROFILE_RESTORED', 'restore': 'PROFILE_RESTORED'}, 'VECTOR_REVOKED': {'snapshot': 'PROFILE_RESTORED', 'restore': 'PROFILE_RESTORED', 'delta': 'RESCORING', 'revoke': 'VECTOR_REVOKED'}, 'PROFILE_RESTORED': {'delta': 'RESCORING', 'revoke': 'VECTOR_REVOKED', 'snapshot': 'PROFILE_RESTORED', 'restore': 'PROFILE_RESTORED'}}


def advance(current: str, action: str) -> str:
    try:
        return TRANSITIONS[current][action]
    except KeyError as exc:
        raise ValueError("illegal lifecycle transition: %s + %s" % (current, action)) from exc
