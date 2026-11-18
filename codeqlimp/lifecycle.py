"""Explicit lifecycle transitions for the two write paths."""
from __future__ import annotations


PHASES = ('EMPTY', 'BASELINED', 'STREAMING', 'WITHDRAWN', 'RECOVERED')
TRANSITIONS = {'EMPTY': {'snapshot': 'BASELINED'}, 'BASELINED': {'delta': 'STREAMING', 'revoke': 'WITHDRAWN', 'snapshot': 'BASELINED'}, 'STREAMING': {'delta': 'STREAMING', 'revoke': 'WITHDRAWN', 'snapshot': 'RECOVERED', 'restore': 'RECOVERED'}, 'WITHDRAWN': {'snapshot': 'RECOVERED', 'restore': 'RECOVERED', 'delta': 'STREAMING', 'revoke': 'WITHDRAWN'}, 'RECOVERED': {'delta': 'STREAMING', 'revoke': 'WITHDRAWN', 'snapshot': 'RECOVERED', 'restore': 'RECOVERED'}}


def advance(current: str, action: str) -> str:
    try:
        return TRANSITIONS[current][action]
    except KeyError as exc:
        raise ValueError("illegal lifecycle transition: %s + %s" % (current, action)) from exc
