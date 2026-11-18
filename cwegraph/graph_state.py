"""Explicit lifecycle transitions for the two write paths."""
from __future__ import annotations


PHASES = ('BLANK', 'GRAPH_LOADED', 'EDGE_FLOW', 'EDGE_REVOKED', 'GRAPH_RESTORED')
TRANSITIONS = {'BLANK': {'snapshot': 'GRAPH_LOADED', 'delta': 'EDGE_FLOW'}, 'GRAPH_LOADED': {'delta': 'EDGE_FLOW', 'revoke': 'EDGE_REVOKED', 'snapshot': 'GRAPH_LOADED'}, 'EDGE_FLOW': {'delta': 'EDGE_FLOW', 'revoke': 'EDGE_REVOKED', 'snapshot': 'GRAPH_RESTORED', 'restore': 'GRAPH_RESTORED'}, 'EDGE_REVOKED': {'snapshot': 'GRAPH_RESTORED', 'restore': 'GRAPH_RESTORED', 'delta': 'EDGE_FLOW', 'revoke': 'EDGE_REVOKED'}, 'GRAPH_RESTORED': {'delta': 'EDGE_FLOW', 'revoke': 'EDGE_REVOKED', 'snapshot': 'GRAPH_RESTORED', 'restore': 'GRAPH_RESTORED'}}


def advance(current: str, action: str) -> str:
    try:
        return TRANSITIONS[current][action]
    except KeyError as exc:
        raise ValueError("illegal lifecycle transition: %s + %s" % (current, action)) from exc
