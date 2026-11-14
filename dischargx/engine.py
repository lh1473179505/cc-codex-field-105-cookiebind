from __future__ import annotations
import base64
import hashlib
import hmac

def _b64url(digest: bytes) -> str:
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

def _key_bytes(secret: str) -> bytes:
    try:
        return bytes.fromhex(secret)
    except ValueError:
        return secret.encode("utf-8")

def _caveat_line(c: dict) -> str | None:
    t = c.get("type")
    if t == "time_before":
        return f"v1|time_before|{c.get('abs_unix')}"
    if t == "exact_path":
        return f"v1|exact_path|{c.get('path')}"
    if t == "method_allow":
        return "v1|method_allow|" + ",".join(c.get("methods") or [])
    if t == "audience":
        return f"v1|audience|{c.get('aud')}"
    if t == "third_party":
        return f"v1|third_party|{c.get('location')}|{c.get('predicate')}|{c.get('ticket_hint')}"
    if t == "predicate_satisfy":
        return f"v1|predicate_satisfy|{c.get('predicate')}"
    return None

def _chain(start_msg: str, caveats: list, secret: str) -> str | None:
    mac = hmac.new(_key_bytes(secret), start_msg.encode("ascii"), hashlib.sha256).digest()
    for c in caveats:
        line = _caveat_line(c)
        if line is None:
            return None
        mac = hmac.new(mac, line.encode("ascii"), hashlib.sha256).digest()
    return _b64url(mac)

def _root_sig(root: dict, secret: str) -> str | None:
    return _chain(f"v1|id|{root.get('identifier')}", root.get("caveats") or [], secret)

def _discharge_sig(dis: dict, secret: str) -> str | None:
    start = f"v1|id|{dis.get('identifier')}|bind|{dis.get('binds_root_sig')}"
    return _chain(start, dis.get("caveats") or [], secret)

def inspect_bundle(bundle: dict) -> dict:
    root = bundle.get("root") or {}
    dis = bundle.get("discharge") or {}
    req = bundle.get("request") or {}
    return {
        "root_kid": root.get("kid"),
        "root_identifier": root.get("identifier"),
        "caveat_types": [c.get("type") for c in (root.get("caveats") or [])],
        "has_discharge": bundle.get("discharge") is not None,
        "discharge_kid": dis.get("kid") if bundle.get("discharge") else None,
        "request_path": req.get("path"),
        "request_method": req.get("method"),
        "nonce": bundle.get("nonce"),
    }

def admit_bundle(bundle: dict, keys: dict, policy: dict, nonce_store: dict, now_unix: int) -> dict:
    root = bundle.get("root") or {}
    dis = bundle.get("discharge")
    req = bundle.get("request") or {}
    policy = policy or {}
    keys = keys or {}
    skew = int(policy.get("clock_skew_seconds", 0))
    reasons: list[str] = []

    def report(decision: str) -> dict:
        return {
            "decision": decision,
            "reason_codes": list(reasons),
            "root_identifier": root.get("identifier"),
            "discharge_identifier": dis.get("identifier") if dis else None,
            "path": req.get("path"),
        }

    # Gate 1: root kid revocation, then root HMAC chain.
    rk = (keys.get("root_keys") or {}).get(root.get("kid"))
    if rk is None:
        reasons.append("root_kid_unknown")
    elif rk.get("status") == "revoked":
        reasons.append("root_revoked")
    else:
        expected = _root_sig(root, rk.get("secret", ""))
        if expected is None or not hmac.compare_digest(expected, str(root.get("sig") or "")):
            reasons.append("root_sig_invalid")
    if reasons:
        return report("deny")

    # Gate 2: first-party caveats vs request and now.
    caveats = root.get("caveats") or []
    third_parties = [c for c in caveats if c.get("type") == "third_party"]
    for c in caveats:
        t = c.get("type")
        if t == "time_before":
            if now_unix > int(c.get("abs_unix")) + skew:
                reasons.append("root_expired")
        elif t == "exact_path":
            if policy.get("path_match") == "exact" and req.get("path") != c.get("path"):
                reasons.append("path_mismatch")
        elif t == "method_allow":
            if req.get("method") not in (c.get("methods") or []):
                reasons.append("method_not_allowed")
        elif t == "audience":
            if policy.get("audience_match") == "exact" and req.get("aud") != c.get("aud"):
                reasons.append("audience_mismatch")
        elif t == "third_party":
            pass
        else:
            reasons.append("unknown_caveat")
    if reasons:
        return report("deny")

    # Gate 3: third-party discharge.
    if third_parties:
        if dis is None:
            if policy.get("require_discharge_for_third_party", True):
                reasons.append("discharge_required")
        else:
            if policy.get("discharge_location_match") == "exact":
                for tp in third_parties:
                    if dis.get("location") != tp.get("location"):
                        reasons.append("discharge_location")
                        break
            dk = (keys.get("discharge_keys") or {}).get(dis.get("kid"))
            discharge_sig_ok = False
            if dk is None:
                reasons.append("discharge_kid_unknown")
            elif dk.get("status") == "revoked":
                reasons.append("discharge_revoked")
            else:
                expected = _discharge_sig(dis, dk.get("secret", ""))
                if expected is None or not hmac.compare_digest(expected, str(dis.get("sig") or "")):
                    reasons.append("discharge_sig_invalid")
                else:
                    discharge_sig_ok = True
            if discharge_sig_ok:
                if dis.get("binds_root_sig") != root.get("sig"):
                    reasons.append("bind_mismatch")
                satisfied = set()
                for c in dis.get("caveats") or []:
                    t = c.get("type")
                    if t == "time_before":
                        if now_unix > int(c.get("abs_unix")) + skew:
                            reasons.append("discharge_expired")
                    elif t == "predicate_satisfy":
                        satisfied.add(c.get("predicate"))
                    else:
                        reasons.append("unknown_caveat")
                if policy.get("predicate_match") == "exact":
                    for tp in third_parties:
                        if tp.get("predicate") not in satisfied:
                            reasons.append("predicate_mismatch")
                            break
    elif dis is not None and policy.get("forbid_extra_discharge", True):
        reasons.append("extra_discharge")
    if reasons:
        return report("deny")

    # Gate 4: nonce replay. Persist only on allow.
    nonce = bundle.get("nonce")
    if nonce is not None:
        nonces = nonce_store.setdefault("nonces", {})
        if nonce in nonces:
            reasons.append("replay")
            return report("deny")
        nonces[nonce] = {"ts": now_unix}

    return report("allow")
