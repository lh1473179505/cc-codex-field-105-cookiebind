from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
from typing import Any

_SIG_FIELDS = ("kid", "table", "chain", "iface", "set", "elem",
               "action", "jump", "priority", "iat", "nonce")


def inspect_rule(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "table": obj.get("table"),
        "chain": obj.get("chain"),
        "iface": obj.get("iface"),
        "set": obj.get("set"),
        "elem": obj.get("elem"),
        "action": obj.get("action"),
        "jump": obj.get("jump"),
        "priority": obj.get("priority"),
        "nonce": obj.get("nonce"),
    }


def _signing_line(obj: dict) -> str:
    return "v1|" + "|".join(str(obj.get(f, "")) for f in _SIG_FIELDS)


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _elem_in_set(elem: str, entries: list) -> bool:
    if elem in entries:
        return True
    try:
        addr = ipaddress.ip_address(elem)
    except ValueError:
        return False
    for entry in entries:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if addr.version == net.version and addr in net:
            return True
    return False


def admit_rule(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    codes: list = []

    if any(f not in obj for f in _SIG_FIELDS + ("sig",)):
        codes.append("missing_fields")

    kid = obj.get("kid")
    key = (keys.get("keys") or {}).get(kid)
    if key is None:
        codes.append("unknown_kid")
    elif key.get("status") != "active":
        codes.append("key_revoked")
    else:
        try:
            secret = bytes.fromhex(key.get("secret", ""))
        except ValueError:
            secret = b""
        expect = hmac.new(secret, _signing_line(obj).encode("utf-8"),
                          hashlib.sha256).digest()
        try:
            got = _b64url_decode(str(obj.get("sig", "")))
        except Exception:
            got = b""
        if not hmac.compare_digest(expect, got):
            codes.append("bad_sig")

    iat = obj.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, int):
        codes.append("bad_iat")
    else:
        skew = int(policy.get("clock_skew_seconds", 0))
        max_age = int(policy.get("max_age_seconds", 0))
        if iat > now_unix + skew:
            codes.append("iat_in_future")
        elif now_unix - iat > max_age:
            codes.append("iat_too_old")

    nonce = obj.get("nonce")
    items = store.get("items")
    if not isinstance(items, dict):
        items = {}
        store["items"] = items
    if not nonce:
        codes.append("nonce_missing")
    elif nonce in items:
        codes.append("nonce_replay")

    table = obj.get("table")
    chain = obj.get("chain")
    iface = obj.get("iface")
    set_name = obj.get("set")
    elem = obj.get("elem")
    action = obj.get("action")
    jump = obj.get("jump")
    priority = obj.get("priority")

    table_ok = table in (policy.get("allowed_tables") or [])
    if not table_ok:
        codes.append("table_not_allowed")
    else:
        chains = (policy.get("allowed_chains") or {}).get(table) or []
        if chain not in chains:
            codes.append("chain_not_allowed")

        ifaces = (policy.get("ifaces") or {}).get(table) or []
        if iface not in ifaces:
            codes.append("iface_not_allowed")

        if (policy.get("set_required_for") or {}).get(table):
            table_sets = (policy.get("sets") or {}).get(table) or {}
            if set_name not in table_sets:
                codes.append("set_not_found")
            elif not _elem_in_set(str(elem), table_sets[set_name]):
                codes.append("elem_not_in_set")

        if action == "jump":
            targets = (policy.get("jump_targets") or {}).get(table) or []
            if not jump:
                codes.append("jump_target_empty")
            elif jump not in targets:
                codes.append("jump_target_not_allowed")
        elif jump:
            codes.append("jump_not_allowed_for_action")

        band = (policy.get("priority_bands") or {}).get(table)
        if band is not None:
            if isinstance(priority, bool) or not isinstance(priority, int) \
                    or not (band[0] <= priority <= band[1]):
                codes.append("priority_out_of_band")

    if action not in (policy.get("allowed_actions") or []):
        codes.append("action_not_allowed")

    for sub in (policy.get("elem_deny_substrings") or []):
        if sub and sub in str(elem):
            codes.append("elem_denied")
            break

    if codes:
        return {"decision": "deny", "reason_codes": codes, "chain": chain}

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "chain": chain}
