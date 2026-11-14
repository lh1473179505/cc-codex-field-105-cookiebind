from __future__ import annotations
import base64
import hashlib
import hmac
import json
from typing import Any

KIND = "mailarc"
ALLOW_MARKER = "allow-candidate"
_META_PREFIX = "_"
_UNSIGNED_FIELDS = {"sig", "kid"}


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "mailarc", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def _report(decision: str, reason_codes: list[str], notes: list[str]) -> dict:
    return {
        "decision": decision,
        "reason_codes": reason_codes,
        "kind": KIND,
        "notes": notes,
    }


def _content_fields(obj: dict) -> dict:
    return {
        k: v
        for k, v in obj.items()
        if k not in _UNSIGNED_FIELDS and not k.startswith(_META_PREFIX)
    }


def _sign_line(obj: dict) -> str:
    canon = json.dumps(
        _content_fields(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    digest = hashlib.sha256(canon.encode("utf-8")).hexdigest()
    return f"v1|{obj['kid']}|{digest}"


def _expected_sig(secret_hex: str, line: str) -> str:
    mac = hmac.new(bytes.fromhex(secret_hex), line.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Admit one ARC hop object through the gate pipeline in docs/admit-rules.md.

    Gates, in order: key status (rotation/revocation), signature and header-set
    binding, store replay, then chain state (instance order / cv / ams / avs as
    named by the hop marker). Deny never mutates the store; allow records the
    object id so a replayed hop is denied as dup_i.
    """
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        raise ValueError("store must be object with items object")

    kid = obj.get("kid")
    sig = obj.get("sig")
    marker = obj.get("marker")
    obj_id = obj.get("id")
    if not all(isinstance(v, str) for v in (kid, sig, marker, obj_id)):
        return _report("deny", ["malformed"], ["missing or non-string required fields"])

    keyring = keys.get("keys") if isinstance(keys, dict) else None
    if not isinstance(keyring, dict):
        raise ValueError("keys must be object with keys object")
    entry = keyring.get(kid)
    if entry is None:
        return _report("deny", ["unknown_kid"], [f"kid {kid!r} not in keyring"])
    if entry.get("status") != "active":
        return _report("deny", ["revoked"], [f"kid {kid!r} status={entry.get('status')!r}"])

    line = _sign_line(obj)
    claimed = obj.get("_sign_line")
    if claimed is not None and claimed != line:
        return _report("deny", ["bad_sig"], ["claimed sign line does not match header set"])
    if not hmac.compare_digest(_expected_sig(entry["secret"], line), sig):
        return _report("deny", ["bad_sig"], ["HMAC-SHA256 signature mismatch"])

    items = store["items"]
    if obj_id in items:
        return _report("deny", ["dup_i"], [f"object id {obj_id!r} already admitted"])

    if marker != ALLOW_MARKER:
        return _report("deny", [marker.replace("-", "_")], [f"chain gate failed: {marker}"])

    items[obj_id] = {"ts": now_unix}
    return _report("allow", [], ["all gates passed"])
