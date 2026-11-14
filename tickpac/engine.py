from __future__ import annotations
from typing import Any

def inspect_ticket(ticket: dict) -> dict:
    pac = ticket.get("pac") or {}
    return {
        "realm": ticket.get("realm"),
        "cname": ticket.get("cname"),
        "spn": ticket.get("spn"),
        "ticket_kid": ticket.get("ticket_kid"),
        "pac_kid": pac.get("pac_kid"),
        "group_sids": list(pac.get("group_sids") or []),
        "deny_sids": list(pac.get("deny_sids") or []),
        "endtime": ticket.get("endtime"),
        "nonce": ticket.get("nonce"),
    }

def admit_ticket(ticket: dict, keys: dict, policy: dict, nonce_store: dict, now_unix: int) -> dict:
    return {
        "decision": "deny",
        "reason_codes": ["not_implemented"],
        "matched_groups": [],
        "spn": ticket.get("spn"),
        "realm": ticket.get("realm"),
    }
