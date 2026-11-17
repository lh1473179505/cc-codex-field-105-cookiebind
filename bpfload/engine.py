from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

SIG_VERSION = "v1"
REQUIRED_FIELDS = (
    "kid", "prog_type", "attach_type", "license", "insn_count",
    "map_refs", "privileged", "iat", "nonce", "sig",
)

def inspect_program(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "prog_type": obj.get("prog_type"),
        "attach_type": obj.get("attach_type"),
        "license": obj.get("license"),
        "insn_count": obj.get("insn_count"),
        "map_refs": obj.get("map_refs"),
        "privileged": obj.get("privileged"),
        "nonce": obj.get("nonce"),
    }

def _deny(obj: dict, code: str) -> dict:
    return {"decision": "deny", "reason_codes": [code], "prog_type": obj.get("prog_type")}

def _signing_input(obj: dict) -> bytes:
    message = "|".join((
        SIG_VERSION,
        str(obj["kid"]),
        str(obj["prog_type"]),
        str(obj["attach_type"]),
        str(obj["license"]),
        str(obj["insn_count"]),
        ",".join(str(m) for m in obj["map_refs"]),
        str(obj["privileged"]),
        str(obj["iat"]),
        str(obj["nonce"]),
    ))
    return message.encode("utf-8")

def _expected_sig(obj: dict, secret: str) -> str:
    digest = hmac.new(bytes.fromhex(secret), _signing_input(obj), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_program(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    missing = [f for f in REQUIRED_FIELDS if f not in obj]
    if missing:
        raise ValueError("missing fields: " + ",".join(missing))
    if not isinstance(obj["map_refs"], list):
        raise ValueError("map_refs must be a list")

    key_entry = keys.get("keys", {}).get(obj["kid"])
    if key_entry is None:
        return _deny(obj, "unknown_kid")
    if key_entry.get("status") != "active":
        return _deny(obj, "revoked")
    if not hmac.compare_digest(_expected_sig(obj, key_entry["secret"]), str(obj["sig"])):
        return _deny(obj, "bad_sig")

    iat = obj["iat"]
    if not isinstance(iat, int) or isinstance(iat, bool):
        return _deny(obj, "iat")
    if iat > now_unix + policy["clock_skew_seconds"] or iat < now_unix - policy["max_age_seconds"]:
        return _deny(obj, "iat")

    programs = policy["programs"]
    prog_type = obj["prog_type"]
    program = programs.get(prog_type)
    if program is None:
        return _deny(obj, "prog_type")
    if prog_type in policy.get("forbidden_prog_types", []):
        return _deny(obj, "forbidden_prog")
    if obj["attach_type"] not in program["attach_types"]:
        return _deny(obj, "attach_type")
    if obj["license"] not in program["licenses"]:
        return _deny(obj, "license")

    insn_count = obj["insn_count"]
    if not isinstance(insn_count, int) or isinstance(insn_count, bool) or insn_count <= 0:
        return _deny(obj, "insn_zero")
    if insn_count < program["insn_min"] or insn_count > program["insn_max"]:
        return _deny(obj, "insn_limit")

    if policy.get("forbid_privileged", False) and obj["privileged"] != 0:
        return _deny(obj, "privileged")

    map_refs = obj["map_refs"]
    registry = policy.get("map_registry", [])
    if any(m not in registry for m in map_refs):
        return _deny(obj, "map_unknown")
    if any(m not in program["maps"] for m in map_refs):
        return _deny(obj, "map_binding")
    if policy.get("require_unique_maps", False) and len(set(map_refs)) != len(map_refs):
        return _deny(obj, "map_duplicate")
    if len(map_refs) > program["map_refs_max"]:
        return _deny(obj, "map_count")

    nonce = obj["nonce"]
    if nonce in store.get("items", {}):
        return _deny(obj, "replay")

    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "prog_type": prog_type}
