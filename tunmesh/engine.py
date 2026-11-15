from __future__ import annotations
from typing import Any

def inspect_peer(peer: dict) -> dict:
    return {
        "kid": peer.get("kid"),
        "pubkey": peer.get("pubkey"),
        "endpoint_host": peer.get("endpoint_host"),
        "endpoint_ip": peer.get("endpoint_ip"),
        "allowed_ips": peer.get("allowed_ips"),
        "keepalive": peer.get("keepalive"),
        "nonce": peer.get("nonce"),
    }

def admit_peer(peer: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "pubkey": peer.get("pubkey")}
