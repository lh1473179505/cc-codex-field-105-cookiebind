from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_mount(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "namespace": obj.get("namespace"),
        "source": obj.get("source"),
        "target": obj.get("target"),
        "fstype": obj.get("fstype"),
        "flags": obj.get("flags"),
        "propagation": obj.get("propagation"),
        "read_only": obj.get("read_only"),
        "nonce": obj.get("nonce"),
    }

def _signature_message(obj: dict) -> str:
    return "v1|{kid}|{namespace}|{source}|{target}|{fstype}|{flags}|{propagation}|{read_only}|{iat}|{nonce}".format(
        kid=obj["kid"],
        namespace=obj["namespace"],
        source=obj["source"],
        target=obj["target"],
        fstype=obj["fstype"],
        flags=",".join(obj["flags"]),
        propagation=obj["propagation"],
        read_only=obj["read_only"],
        iat=obj["iat"],
        nonce=obj["nonce"],
    )

def _expected_sig(secret_hex: str, message: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), message.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def _safe_path(value: Any, deny_substrings: list) -> bool:
    if not isinstance(value, str) or not value.startswith("/"):
        return False
    for sub in deny_substrings:
        if sub and sub in value:
            return False
    for comp in value.split("/")[1:]:
        if comp in ("", ".", ".."):
            return False
    return True

def admit_mount(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    target = obj.get("target") if isinstance(obj, dict) else None

    def deny(code: str) -> dict:
        return {"decision": "deny", "reason_codes": [code], "target": target}

    if not isinstance(obj, dict):
        return {"decision": "deny", "reason_codes": ["shape"], "target": None}

    kid = obj.get("kid")
    key_entry = (keys.get("keys") or {}).get(kid)
    if key_entry is None:
        return deny("unknown_kid")
    if key_entry.get("status") != "active":
        return deny("key_revoked")

    flags = obj.get("flags")
    read_only = obj.get("read_only")
    iat = obj.get("iat")
    nonce = obj.get("nonce")
    sig = obj.get("sig")
    if (
        not isinstance(obj.get("namespace"), str)
        or not isinstance(obj.get("source"), str)
        or not isinstance(target, str)
        or not isinstance(obj.get("fstype"), str)
        or not isinstance(obj.get("propagation"), str)
        or not isinstance(flags, list)
        or not all(isinstance(f, str) for f in flags)
        or not isinstance(read_only, int)
        or isinstance(read_only, bool)
        or not isinstance(iat, int)
        or isinstance(iat, bool)
        or not isinstance(nonce, str)
        or not isinstance(sig, str)
    ):
        return deny("shape")

    expected = _expected_sig(key_entry["secret"], _signature_message(obj))
    if not hmac.compare_digest(expected, sig):
        return deny("bad_signature")

    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if iat > now_unix + skew or now_unix - iat > max_age:
        return deny("iat_freshness")

    namespaces = policy.get("namespaces") or {}
    ns = namespaces.get(obj["namespace"])
    if ns is None:
        return deny("namespace")

    deny_substrings = policy.get("path_deny_substrings") or []
    source = obj["source"]
    if not _safe_path(source, deny_substrings):
        return deny("source_path")
    if not _safe_path(target, deny_substrings):
        return deny("target_path")

    if source not in (ns.get("sources") or []):
        return deny("source")
    if not any(target.startswith(prefix) for prefix in (ns.get("target_prefixes") or [])):
        return deny("target_prefix")

    fstype = obj["fstype"]
    if fstype not in (ns.get("fstypes") or []):
        return deny("fstype")

    if policy.get("require_unique_flags") and len(set(flags)) != len(flags):
        return deny("flags_unique")
    allowed_flags = set(ns.get("flags") or [])
    if not set(flags) <= allowed_flags:
        return deny("flags_subset")
    if not set(ns.get("required_flags") or []) <= set(flags):
        return deny("flags_required")

    if obj["propagation"] != ns.get("propagation"):
        return deny("propagation")

    if read_only not in (policy.get("read_only_values") or [0, 1]):
        return deny("read_only")

    if fstype == "bind":
        if source not in (ns.get("bind_sources") or []):
            return deny("bind_source")
        if read_only != 1:
            return deny("bind_writable")

    items = store.get("items")
    if not isinstance(items, dict):
        return deny("store_shape")
    if nonce in items:
        return deny("replay")

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": reasons, "target": target}
