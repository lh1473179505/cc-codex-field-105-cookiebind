"""Explicit lifecycle transitions for the two write paths."""
from __future__ import annotations


PHASES = ('WAITING', 'SBOM_READY', 'FEED_SYNC', 'MATCH_WITHDRAWN', 'FEED_RESTORED')
TRANSITIONS = {'WAITING': {'snapshot': 'SBOM_READY', 'delta': 'FEED_SYNC'}, 'SBOM_READY': {'delta': 'FEED_SYNC', 'revoke': 'MATCH_WITHDRAWN', 'snapshot': 'SBOM_READY'}, 'FEED_SYNC': {'delta': 'FEED_SYNC', 'revoke': 'MATCH_WITHDRAWN', 'snapshot': 'FEED_RESTORED', 'restore': 'FEED_RESTORED'}, 'MATCH_WITHDRAWN': {'snapshot': 'FEED_RESTORED', 'restore': 'FEED_RESTORED', 'delta': 'FEED_SYNC', 'revoke': 'MATCH_WITHDRAWN'}, 'FEED_RESTORED': {'delta': 'FEED_SYNC', 'revoke': 'MATCH_WITHDRAWN', 'snapshot': 'FEED_RESTORED', 'restore': 'FEED_RESTORED'}}


def advance(current: str, action: str) -> str:
    try:
        return TRANSITIONS[current][action]
    except KeyError as exc:
        raise ValueError("illegal lifecycle transition: %s + %s" % (current, action)) from exc
