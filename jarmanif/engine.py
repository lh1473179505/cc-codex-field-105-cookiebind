from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_archive(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "main_class": obj.get("main_class"),
        "impl_title": obj.get("impl_title"),
        "sealing": obj.get("sealing"),
        "entries": obj.get("entries"),
        "svc_line": obj.get("svc_line"),
        "alg": obj.get("alg"),
        "nonce": obj.get("nonce"),
    }

def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _sign_line(obj: dict) -> str:
    entries = obj.get("entries") or []
    paths = ",".join(f"{e.get('path')}={e.get('sha256')}" for e in entries)
    required = ",".join(obj.get("required_files") or [])
    return (
        f"v1|{obj.get('kid')}|{obj.get('main_class')}|{obj.get('impl_title')}"
        f"|{obj.get('sealing')}|{paths}|{required}|{obj.get('svc_line')}"
        f"|{obj.get('alg')}|{obj.get('total_size')}|{obj.get('created')}|{obj.get('nonce')}"
    )

def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _implied_contents(path: str, obj: dict) -> set[bytes] | None:
    if path == "META-INF/MANIFEST.MF":
        return {b"Manifest-Version: 1.0\n"}
    if path.startswith("META-INF/services/"):
        return {((obj.get("svc_line") or "") + "\n").encode("utf-8")}
    if path.endswith(".class"):
        title = obj.get("impl_title") or ""
        return {("class-bytes-" + tok).encode("utf-8") for tok in title.split("-") if tok}
    return None

def admit_archive(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    entries = obj.get("entries") or []
    body_map = obj.get("body_sha256") or {}

    # Path safety (before prefix allow).
    deny_subs = policy.get("path_deny_substrings") or []
    seen: set[str] = set()
    for e in entries:
        p = e.get("path") or ""
        if any(s in p for s in deny_subs):
            reasons.append("path_deny")
        if policy.get("forbid_absolute") and p.startswith("/"):
            reasons.append("path_absolute")
        if policy.get("forbid_duplicate_paths"):
            if p in seen:
                reasons.append("path_duplicate")
            seen.add(p)

    # Prefix allow.
    prefixes = policy.get("allowed_path_prefixes") or []
    for e in entries:
        p = e.get("path") or ""
        if not any(p.startswith(pre) for pre in prefixes):
            reasons.append("path_prefix")

    # Main binding.
    mains = policy.get("mains") or {}
    main_class = obj.get("main_class")
    bound = mains.get(main_class)
    if bound is None:
        reasons.append("main_unknown")
    else:
        if obj.get("impl_title") != bound.get("impl_title"):
            reasons.append("title_mismatch")
        if obj.get("sealing") != bound.get("sealing"):
            reasons.append("sealing_mismatch")
        if obj.get("svc_line") != bound.get("svc_line"):
            reasons.append("svc_mismatch")

    # Required files.
    required_all = policy.get("required_files_all") or []
    paths_present = {e.get("path") for e in entries}
    for name in required_all:
        if name not in paths_present:
            reasons.append("required_missing")
    if list(obj.get("required_files") or []) != list(required_all):
        reasons.append("required_mismatch")

    # Body / size / alg.
    if len(entries) > (policy.get("max_entries") or 0):
        reasons.append("too_many_entries")
    max_entry = policy.get("max_entry_size")
    total = 0
    for e in entries:
        size = e.get("size") or 0
        total += size
        if max_entry is not None and size > max_entry:
            reasons.append("entry_too_large")
    if obj.get("total_size") != total:
        reasons.append("total_mismatch")
    max_total = policy.get("max_total_size")
    if max_total is not None and (obj.get("total_size") or 0) > max_total:
        reasons.append("total_too_large")
    if obj.get("alg") not in (policy.get("allowed_algs") or []):
        reasons.append("alg_denied")
    if policy.get("require_body_sha_match"):
        for e in entries:
            p = e.get("path") or ""
            body = body_map.get(p)
            if body is None:
                reasons.append("body_mismatch")
                continue
            implied = _implied_contents(p, obj)
            if implied is None:
                continue
            ok = any(
                _sha256(c) == body and _sha256(p.encode("utf-8") + b"\x00" + c) == e.get("sha256")
                for c in implied
            )
            if not ok:
                reasons.append("body_mismatch")

    # Time window.
    created = obj.get("created")
    if not isinstance(created, int):
        reasons.append("created_invalid")
    else:
        skew = policy.get("clock_skew_seconds") or 0
        max_age = policy.get("max_age_seconds")
        if created > now_unix + skew:
            reasons.append("created_future")
        if max_age is not None and now_unix - created > max_age:
            reasons.append("stale")

    # HMAC + revocation.
    kid = obj.get("kid")
    key_rec = (keys.get("keys") or {}).get(kid)
    if key_rec is None:
        reasons.append("kid_unknown")
    else:
        if key_rec.get("status") == "revoked":
            reasons.append("kid_revoked")
        secret = bytes.fromhex(key_rec.get("secret") or "")
        expect = _b64url_nopad(hmac.new(secret, _sign_line(obj).encode("utf-8"), hashlib.sha256).digest())
        if not hmac.compare_digest(expect, obj.get("sig") or ""):
            reasons.append("sig_invalid")

    # Replay.
    nonce = obj.get("nonce")
    items = store.get("items")
    if not isinstance(items, dict):
        items = {}
    if nonce in items:
        reasons.append("replay")

    decision = "allow" if not reasons else "deny"
    if decision == "allow":
        store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": decision, "reason_codes": reasons, "main_class": main_class}
