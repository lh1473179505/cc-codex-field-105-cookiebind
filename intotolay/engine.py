from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

_HEX_LOWER = set("0123456789abcdef")


def inspect_layout(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "supply_chain": obj.get("supply_chain"),
        "step_name": obj.get("step_name"),
        "pubkey_ids": obj.get("pubkey_ids"),
        "threshold": obj.get("threshold"),
        "artifact_rules": obj.get("artifact_rules"),
        "layout_sha256": obj.get("layout_sha256"),
        "nonce": obj.get("nonce"),
    }


def _signed_message(obj: dict) -> bytes:
    parts = [
        "v1",
        str(obj.get("kid")),
        str(obj.get("supply_chain")),
        str(obj.get("step_name")),
        ",".join(obj.get("pubkey_ids") or []),
        str(obj.get("threshold")),
        ",".join(obj.get("artifact_rules") or []),
        str(obj.get("layout_sha256")),
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ]
    return "|".join(parts).encode("utf-8")


def _b64url_decode(sig: str) -> bytes:
    pad = "=" * (-len(sig) % 4)
    return base64.urlsafe_b64decode(sig + pad)


def _valid_artifact_path(path: str, step: dict, policy: dict) -> bool:
    if not path or path.startswith("/"):
        return False
    for bad in policy.get("artifact_path_deny_substrings", []):
        if bad and bad in path:
            return False
    components = path.split("/")
    if components[-1] == "*":
        components = components[:-1]
        if not components:
            return False
    for comp in components:
        if comp in ("", ".", ".."):
            return False
    prefixes = step.get("artifact_path_prefixes", [])
    base = "/".join(components)
    if path.endswith("/*"):
        base += "/"
    return any(base.startswith(prefix) for prefix in prefixes)


def admit_layout(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    step_name = obj.get("step_name")

    chains = policy.get("supply_chains", {})
    chain = chains.get(obj.get("supply_chain"))
    step = None
    if chain is None:
        reasons.append("supply_chain_unknown")
    else:
        step = chain.get("steps", {}).get(step_name)
        if step is None:
            reasons.append("step_unknown")

    pubkey_ids = obj.get("pubkey_ids")
    unique_ids: list[str] = []
    if not isinstance(pubkey_ids, list) or not pubkey_ids or not all(
        isinstance(p, str) for p in pubkey_ids
    ):
        reasons.append("pubkey_ids_invalid")
        pubkey_ids = []
    else:
        seen = set()
        for pid in pubkey_ids:
            if pid in seen:
                reasons.append("pubkey_duplicate")
                break
            seen.add(pid)
        unique_ids = list(dict.fromkeys(pubkey_ids))

    threshold = obj.get("threshold")
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        reasons.append("threshold_invalid")
        threshold = None

    artifact_rules = obj.get("artifact_rules")
    if not isinstance(artifact_rules, list) or not all(
        isinstance(r, str) for r in artifact_rules
    ):
        reasons.append("artifact_rules_invalid")
        artifact_rules = []

    if step is not None:
        allowed = set(step.get("pubkeys_allowed", []))
        required = set(step.get("pubkeys_required", []))
        if any(pid not in allowed for pid in pubkey_ids):
            reasons.append("pubkey_not_allowed")
        if not required.issubset(set(pubkey_ids)):
            reasons.append("pubkey_required_missing")

        if threshold is not None:
            tmin = step.get("threshold_min")
            tmax = step.get("threshold_max")
            if tmin is not None and threshold < tmin:
                reasons.append("threshold_below_min")
            if tmax is not None and threshold > tmax:
                reasons.append("threshold_above_max")
            if threshold > len(unique_ids):
                reasons.append("threshold_exceeds_keys")

        if len(artifact_rules) > policy.get("artifact_rule_max", 0):
            reasons.append("artifact_rule_max_exceeded")
        verbs = set(step.get("artifact_verbs", []))
        for rule in artifact_rules:
            if rule.count(" ") != 1:
                reasons.append("artifact_rule_format")
                continue
            verb, path = rule.split(" ")
            if verb not in verbs:
                reasons.append("artifact_verb")
            if not _valid_artifact_path(path, step, policy):
                reasons.append("artifact_path")
        for req in step.get("artifact_rules_required", []):
            if req not in artifact_rules:
                reasons.append("artifact_rule_required_missing")

    digest = obj.get("layout_sha256")
    want_len = policy.get("layout_sha256_hex_len", 64)
    if (
        not isinstance(digest, str)
        or len(digest) != want_len
        or any(c not in _HEX_LOWER for c in digest)
    ):
        reasons.append("layout_sha256_invalid")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("iat_invalid")
    else:
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            reasons.append("iat_future")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("iat_stale")

    key_entry = keys.get("keys", {}).get(obj.get("kid"))
    secret = None
    if key_entry is None:
        reasons.append("key_unknown")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")
    else:
        secret = key_entry.get("secret")

    if secret is not None:
        try:
            key_bytes = bytes.fromhex(secret)
        except ValueError:
            key_bytes = str(secret).encode("utf-8")
        expect = hmac.new(key_bytes, _signed_message(obj), hashlib.sha256).digest()
        provided = obj.get("sig")
        ok = False
        if isinstance(provided, str):
            try:
                ok = hmac.compare_digest(expect, _b64url_decode(provided))
            except Exception:
                ok = False
        if not ok:
            reasons.append("signature_invalid")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in store.get("items", {}):
        reasons.append("replay")

    if reasons:
        return {
            "decision": "deny",
            "reason_codes": sorted(set(reasons)),
            "step_name": step_name,
        }
    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "step_name": step_name}
