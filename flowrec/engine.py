from __future__ import annotations
from typing import Any

def inspect_flow(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "exporter": obj.get("exporter"),
        "src_ip": obj.get("src_ip"),
        "dst_ip": obj.get("dst_ip"),
        "src_port": obj.get("src_port"),
        "dst_port": obj.get("dst_port"),
        "protocol": obj.get("protocol"),
        "packets": obj.get("packets"),
        "bytes": obj.get("bytes"),
        "start_time": obj.get("start_time"),
        "end_time": obj.get("end_time"),
        "nonce": obj.get("nonce"),
    }

def admit_flow(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "exporter": obj.get("exporter")}
