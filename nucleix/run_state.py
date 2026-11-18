"""Explicit lifecycle transitions for the two write paths."""
from __future__ import annotations


PHASES = ('CREATED', 'HOST_BASELINED', 'PROBING', 'ALERT_CLOSED', 'HOST_RECOVERED')
TRANSITIONS = {'CREATED': {'snapshot': 'HOST_BASELINED'}, 'HOST_BASELINED': {'delta': 'PROBING', 'revoke': 'ALERT_CLOSED', 'snapshot': 'HOST_BASELINED', 'restore': 'HOST_RECOVERED'}, 'PROBING': {'delta': 'PROBING', 'revoke': 'ALERT_CLOSED', 'snapshot': 'HOST_RECOVERED', 'restore': 'HOST_RECOVERED'}, 'ALERT_CLOSED': {'snapshot': 'HOST_RECOVERED', 'restore': 'HOST_RECOVERED', 'delta': 'PROBING', 'revoke': 'ALERT_CLOSED'}, 'HOST_RECOVERED': {'delta': 'PROBING', 'revoke': 'ALERT_CLOSED', 'snapshot': 'HOST_RECOVERED', 'restore': 'HOST_RECOVERED'}}


def advance(current: str, action: str) -> str:
    try:
        return TRANSITIONS[current][action]
    except KeyError as exc:
        raise ValueError("illegal lifecycle transition: %s + %s" % (current, action)) from exc
