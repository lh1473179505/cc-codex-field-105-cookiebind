from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_msg(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "from_addr": obj.get("from_addr"),
        "return_path": obj.get("return_path"),
        "dkim_d": obj.get("dkim_d"),
        "arc_i": obj.get("arc_i"),
        "cv": obj.get("cv"),
        "body_sha256": obj.get("body_sha256"),
        "nonce": obj.get("nonce"),
    }

def _split_addr(addr: Any) -> tuple[str, str] | None:
    if not isinstance(addr, str) or addr.count("@") != 1:
        return None
    local, domain = addr.split("@")
    if not local or not domain:
        return None
    return local, domain

def _signing_line(kid, from_addr, return_path, dkim_d, arc_i, cv, body_sha256, relay, iat, nonce) -> str:
    return "|".join(["v1", str(kid), str(from_addr), str(return_path), str(dkim_d),
                     str(arc_i), str(cv), str(body_sha256), str(relay), str(iat), str(nonce)])

def _is_hex(s: Any, length: int) -> bool:
    return isinstance(s, str) and len(s) == length and all(c in "0123456789abcdefABCDEF" for c in s)

def admit_msg(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    codes: list[str] = []
    from_addr = obj.get("from_addr")
    return_path = obj.get("return_path")
    dkim_d = obj.get("dkim_d")
    arc_i = obj.get("arc_i")
    cv = obj.get("cv")
    body_sha256 = obj.get("body_sha256")
    relay = obj.get("relay")
    nonce = obj.get("nonce")
    iat = obj.get("iat")
    kid = obj.get("kid")
    sig = obj.get("sig")

    deny_subs = policy.get("addr_deny_substrings", [])
    for addr in (from_addr, return_path):
        if isinstance(addr, str) and any(sub in addr for sub in deny_subs):
            codes.append("addr_deny_substring")
            break

    parsed_from = _split_addr(from_addr)
    dom_policy = None
    if parsed_from is None:
        codes.append("from_addr_malformed")
    else:
        local, domain = parsed_from
        if local in policy.get("from_local_deny", []):
            codes.append("from_local_deny")
        dom_policy = policy.get("from_domains", {}).get(domain)
        if dom_policy is None:
            codes.append("from_domain_not_allowed")

    parsed_rp = _split_addr(return_path)
    if parsed_rp is None:
        codes.append("return_path_malformed")
    elif dom_policy is not None and parsed_rp[1] not in dom_policy.get("return_path_domains", []):
        codes.append("return_path_domain_mismatch")

    if dom_policy is not None and dkim_d not in dom_policy.get("dkim_d", []):
        codes.append("dkim_d_mismatch")

    if not isinstance(arc_i, int) or isinstance(arc_i, bool):
        codes.append("arc_i_invalid")
    elif dom_policy is not None and not (0 <= arc_i <= dom_policy.get("arc_i_max", 0)):
        codes.append("arc_i_exceeded")

    if policy.get("forbid_cv_fail") and cv == "fail":
        codes.append("cv_fail")
    if dom_policy is not None and cv not in dom_policy.get("cv_allow", []):
        codes.append("cv_not_allowed")

    if dom_policy is None or dom_policy.get("require_body_hash"):
        if not _is_hex(body_sha256, policy.get("body_sha256_len", 64)):
            codes.append("body_sha256_invalid")

    if dom_policy is not None and relay not in dom_policy.get("allowed_relays", []):
        codes.append("relay_not_allowed")

    key_entry = keys.get("keys", {}).get(kid) if isinstance(kid, str) else None
    if key_entry is None:
        codes.append("kid_unknown")
    elif key_entry.get("status") != "active":
        codes.append("key_revoked")
    else:
        line = _signing_line(kid, from_addr, return_path, dkim_d, arc_i, cv,
                             body_sha256, relay, iat, nonce)
        expected = base64.urlsafe_b64encode(
            hmac.new(bytes.fromhex(key_entry["secret"]), line.encode("utf-8"),
                     hashlib.sha256).digest()).rstrip(b"=").decode("ascii")
        if not isinstance(sig, str) or not hmac.compare_digest(expected, sig):
            codes.append("sig_invalid")

    if not isinstance(iat, int) or isinstance(iat, bool):
        codes.append("iat_invalid")
    else:
        if iat - now_unix > policy.get("clock_skew_seconds", 0):
            codes.append("iat_future")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            codes.append("iat_expired")

    if not isinstance(nonce, str) or not nonce:
        codes.append("nonce_invalid")
    elif nonce in store.get("items", {}):
        codes.append("nonce_replay")

    if codes:
        return {"decision": "deny", "reason_codes": codes, "from_addr": from_addr}

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "from_addr": from_addr}
