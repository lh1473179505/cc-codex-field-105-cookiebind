from __future__ import annotations
import base64
import hashlib
import hmac
import json
from typing import Any

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "gitgpgx", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}

def _canonical(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

def _content_fields(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in ("kid", "sig") and not k.startswith("_")}

def _tree_hash(obj: dict) -> str:
    return hashlib.sha256(_canonical(_content_fields(obj))).hexdigest()

def _sign_line(obj: dict, tree: str) -> str:
    parents = obj.get("parents") or []
    trailers = obj.get("trailers") or {}
    parents_csv = ",".join(sorted(str(p) for p in parents))
    trailer_sha = hashlib.sha256(_canonical(trailers)).hexdigest() if trailers else ""
    parts = ["v1", obj["kid"], tree, parents_csv, trailer_sha]
    while parts and parts[-1] == "":
        parts.pop()
    return "|".join(parts)

def _sig_for(secret: bytes, line: str) -> str:
    mac = hmac.new(secret, line.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")

def _key_level(entry: dict) -> int:
    if "level" in entry:
        return int(entry["level"])
    return 1 if entry.get("status") == "active" else 0

def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate admit gates per docs/admit-rules.md.

    On allow the admitted object id is recorded into ``store["items"]``
    (caller persists); on deny the store is left untouched.
    """
    if not isinstance(obj, dict) or not isinstance(obj.get("kid"), str) or not isinstance(obj.get("sig"), str):
        raise ValueError("input object must be a JSON object with string kid and sig")
    policy = policy or {}
    store = store or {"items": {}}
    items = store.get("items")
    if not isinstance(items, dict):
        raise ValueError("store must be object with items object")
    keyring = (keys or {}).get("keys", keys or {})
    if not isinstance(keyring, dict):
        raise ValueError("keys must be object with keys object")
    skew = int(policy.get("clock_skew_seconds", 0))
    pkg = policy.get("pkg", "gitgpgx")

    reasons: list[str] = []

    kid = obj["kid"]
    entry = keyring.get(kid)
    if not isinstance(entry, dict):
        reasons.append("kid_unknown")
        entry = None
    if entry is not None:
        if entry.get("status") == "revoked":
            reasons.append("kid_revoked")
        if _key_level(entry) < int(policy.get("min_trust", 1)):
            reasons.append("trust_below_min")
        key_exp = entry.get("expires")
        if key_exp is not None and now_unix is not None and now_unix > int(key_exp) + skew:
            reasons.append("key_expired")

    obj_exp = obj.get("expires")
    if obj_exp is not None and now_unix is not None and now_unix > int(obj_exp) + skew:
        reasons.append("expired")

    roots = policy.get("allowed_path_roots") or ["/v1/{}/".format(pkg)]
    path = obj.get("path")
    if not isinstance(path, str) or not any(path.startswith(root) for root in roots):
        reasons.append("tree_root_mismatch")

    parents = obj.get("parents") or []
    if set(str(p) for p in parents) != set(items.keys()):
        reasons.append("parents_mismatch")

    required_trailers = policy.get("required_trailers") or {}
    trailers = obj.get("trailers") or {}
    for tkey, tval in required_trailers.items():
        if tkey not in trailers:
            reasons.append("trailer_missing")
        elif trailers[tkey] != tval:
            reasons.append("trailer_mismatch")

    tree = _tree_hash(obj)
    if entry is not None and entry.get("secret") is not None:
        try:
            secret = bytes.fromhex(str(entry["secret"]))
        except ValueError:
            secret = str(entry["secret"]).encode("utf-8")
        expected = _sig_for(secret, _sign_line(obj, tree))
        if not hmac.compare_digest(expected, obj["sig"]):
            reasons.append("sig_mismatch")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "kind": pkg, "notes": []}

    sid = obj.get("id")
    if not isinstance(sid, str) or not sid:
        sid = tree
    items[sid] = {"ts": now_unix} if now_unix is not None else {}
    return {"decision": "allow", "reason_codes": [], "kind": pkg, "notes": []}
