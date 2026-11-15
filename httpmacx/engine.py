from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_request(request: dict) -> dict:
    return {
        "method": request.get("method"),
        "authority": request.get("authority"),
        "path": request.get("path"),
        "kid": request.get("kid"),
        "covered": list(request.get("covered") or []),
        "nonce": request.get("nonce"),
    }

def admit_request(request: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    authority = request.get("authority")
    path = request.get("path")

    def report(decision: str) -> dict:
        return {
            "decision": decision,
            "reason_codes": reasons,
            "authority": authority,
            "path": path,
        }

    covered = list(request.get("covered") or [])
    kid = request.get("kid")

    # Gate 1: recompute base string, verify signature, key status.
    key_entry = (keys.get("keys") or {}).get(kid)
    if key_entry is None:
        reasons.append("unknown_key")
        return report("deny")
    if key_entry.get("status") != "active":
        reasons.append("key_revoked")
        return report("deny")
    try:
        base_string = _base_string(request, covered)
    except ValueError:
        reasons.append("unknown_covered_component")
        return report("deny")
    secret = bytes.fromhex(key_entry["secret"])
    expected = hmac.new(secret, base_string.encode("utf-8"), hashlib.sha256).digest()
    try:
        actual = base64.urlsafe_b64decode(_pad_b64(str(request.get("sig") or "")))
    except Exception:
        actual = b""
    if not hmac.compare_digest(expected, actual):
        reasons.append("bad_signature")
        return report("deny")

    # Gate 2: required covered components must be present.
    missing = [c for c in (policy.get("required_covered") or []) if c not in covered]
    if missing:
        reasons.append("missing_covered")

    # Gate 3: method / authority / path prefix / query in path.
    if request.get("method") not in (policy.get("allowed_methods") or []):
        reasons.append("method_not_allowed")
    if authority not in (policy.get("allowed_authorities") or []):
        reasons.append("authority_not_allowed")
    prefixes = policy.get("allowed_path_prefixes") or []
    if not any(isinstance(path, str) and path.startswith(p) for p in prefixes):
        reasons.append("path_not_allowed")
    if policy.get("forbid_query_in_path") and isinstance(path, str) and "?" in path:
        reasons.append("query_in_path")

    # Gate 4: content-type allow; content-digest must match body.
    if request.get("content_type") not in (policy.get("allowed_content_types") or []):
        reasons.append("content_type_not_allowed")
    body_b64 = request.get("body_b64")
    if body_b64 is not None:
        digest = "sha-256=:" + base64.urlsafe_b64encode(
            hashlib.sha256(base64.urlsafe_b64decode(_pad_b64(str(body_b64)))).digest()
        ).rstrip(b"=").decode("ascii") + ":"
        if request.get("content_digest") != digest:
            reasons.append("digest_mismatch")

    # Gate 5: created/expires time window with skew.
    skew = int(policy.get("clock_skew_seconds") or 0)
    created = request.get("created")
    expires = request.get("expires")
    if not isinstance(created, int) or not isinstance(expires, int):
        reasons.append("missing_signature_params")
    else:
        if created - skew > now_unix:
            reasons.append("not_yet_valid")
        if now_unix > expires + skew:
            reasons.append("expired")

    # Gate 6: nonce replay.
    nonce = request.get("nonce")
    items = store.setdefault("items", {})
    if nonce is not None and nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return report("deny")
    if nonce is not None:
        items[nonce] = {"ts": now_unix}
    return report("allow")


def _pad_b64(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def _base_string(request: dict, covered: list[str]) -> str:
    lines = []
    for name in covered:
        lines.append(f'"{name}": {_component_value(request, name)}')
    params = " ".join(f'"{c}"' for c in covered)
    lines.append(
        f'"@signature-params": ({params});created={request.get("created")}'
        f';expires={request.get("expires")};keyid="{request.get("kid")}"'
        f';nonce="{request.get("nonce")}"'
    )
    return "\n".join(lines)


def _component_value(request: dict, name: str) -> str:
    if name == "@method":
        return str(request.get("method"))
    if name == "@authority":
        return str(request.get("authority"))
    if name == "@path":
        return str(request.get("path"))
    if name == "content-digest":
        return str(request.get("content_digest"))
    if name == "content-type":
        return str(request.get("content_type"))
    headers = request.get("headers") or {}
    if name in headers:
        return str(headers[name])
    raise ValueError(f"unknown covered component: {name}")
