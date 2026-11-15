from __future__ import annotations
import base64
import hashlib
import hmac
import json
from typing import Any

_REQUIRED_STR_FIELDS = ("id", "path", "kid", "sig")
_UNSIGNED_FIELDS = {"sig", "kid"}


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "opaish", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def _canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _query_path(obj: Any, path: str) -> Any:
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict):
            if part not in cur:
                return None
            cur = cur[part]
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
    return cur


def _match_condition(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        if len(expected) != 1:
            return False
        op, operand = next(iter(expected.items()))
        if op == "eq":
            return actual == operand
        if op == "prefix":
            return isinstance(actual, str) and isinstance(operand, str) and actual.startswith(operand)
        if op == "in":
            return isinstance(operand, list) and actual in operand
        return False
    return actual == expected


def _rule_matches(rule: dict, obj: dict) -> bool:
    match = rule.get("match", {})
    if not isinstance(match, dict):
        return False
    for field_path, expected in match.items():
        if not _match_condition(_query_path(obj, field_path), expected):
            return False
    return True


def _signed_payload(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in _UNSIGNED_FIELDS and not k.startswith("_")}


def _sign_line(kid: str, input_sha: str, rules: list) -> str:
    line = f"v1|{kid}|{input_sha}"
    if rules:
        line += "|" + _sha256_hex(_canon(rules))
    return line


def _secret_bytes(entry: dict) -> bytes:
    secret = entry.get("secret", "")
    if isinstance(secret, str):
        try:
            return bytes.fromhex(secret)
        except ValueError:
            return secret.encode("utf-8")
    return b""


def _report(decision: str, reason_codes: list[str], kind: str, notes: list[str]) -> dict:
    return {"decision": decision, "reason_codes": reason_codes, "kind": kind, "notes": notes}


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Admit or deny an input object per docs/admit-rules.md.

    Gates run in order; the first failing gate decides the reason code.
    On allow the object id is recorded in ``store["items"]`` (replay guard);
    on deny the store is left untouched.
    """
    if not isinstance(policy, dict):
        raise ValueError("policy must be an object")
    if not isinstance(keys, dict):
        raise ValueError("keys must be an object")
    if not isinstance(store, dict) or not isinstance(store.get("items", {}), dict):
        raise ValueError("store must be object with items object")

    pkg = policy.get("pkg", "opaish")
    kind = pkg if isinstance(pkg, str) else "opaish"

    def deny(code: str, note: str) -> dict:
        return _report("deny", [code], kind, [note])

    if not isinstance(obj, dict):
        return deny("invalid_type", "input must be an object")
    for field in _REQUIRED_STR_FIELDS:
        if not isinstance(obj.get(field), str):
            return deny("invalid_type", f"field {field!r} must be a string")

    key_map = keys.get("keys", keys)
    if not isinstance(key_map, dict):
        raise ValueError("keys must contain a keys object")
    entry = key_map.get(obj["kid"])
    if not isinstance(entry, dict):
        return deny("unknown_kid", "kid is not present in the key store")
    if entry.get("status") != "active":
        return deny("kid_revoked", "kid is revoked")

    rules = policy.get("rules") or []
    if not isinstance(rules, list):
        raise ValueError("policy rules must be a list")
    input_sha = _sha256_hex(_canon(_signed_payload(obj)))
    line = _sign_line(obj["kid"], input_sha, rules)
    expected = _b64url(hmac.new(_secret_bytes(entry), line.encode("utf-8"), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, obj["sig"]):
        return deny("bad_signature", "signature does not match the signing input")

    items = store.setdefault("items", {})
    obj_id = obj["id"]
    if obj_id in items:
        return deny("replay_detected", "id was already admitted")

    effective_rules = list(rules) + [
        {"effect": "allow", "match": {"path": {"prefix": f"/v1/{kind}/"}}}
    ]
    for rule in effective_rules:
        if not isinstance(rule, dict):
            raise ValueError("each rule must be an object")
        effect = rule.get("effect")
        if effect not in ("allow", "deny"):
            raise ValueError("rule effect must be allow or deny")
        if not _rule_matches(rule, obj):
            continue
        if effect == "allow":
            items[obj_id] = {"ts": now_unix}
            return _report("allow", [], kind, [])
        reason = rule.get("reason")
        code = reason if isinstance(reason, str) and reason else "deny_rule"
        return deny(code, "matched an explicit deny rule")

    return deny("default_deny", "no rule matched; default deny")
