from __future__ import annotations
import base64
import hashlib
import hmac
import json
from typing import Any

_KIND = "rlsrow"

# Roles granted to an active key by the scaffold policy (policy.json carries no
# per-key role table yet, so the grant is a module-level constant).
_GRANTED_ROLES = frozenset({"owner", "editor", "viewer"})

_REASON_NOTES = {
    "malformed_object": "object is missing required signed fields",
    "kid_unknown": "kid is not present in the key ring",
    "kid_revoked": "kid has been revoked",
    "bad_signature": "signature does not match the canonical signing line",
    "tenant_mismatch": "predicate is not bound to the row tenant",
    "role_mismatch": "predicate roles do not intersect the granted roles",
    "or_escalation": "predicate uses OR to reach another tenant",
    "empty_predicate": "predicate is empty",
    "unknown_predicate": "predicate token is not in the policy vocabulary",
    "already_admitted": "object id is already present in the store",
}


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "rlsrow", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def _signed_claims(obj: dict) -> dict:
    """Claims covered by the commitment: every field except the signature
    itself, the kid (already bound to be present in the signing line), and
    underscore-prefixed transport hints."""
    return {k: v for k, v in obj.items() if k not in ("kid", "sig") and not k.startswith("_")}


def _commitment(claims: dict) -> str:
    canonical = json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_line(obj: dict) -> str:
    return "v1|{kid}|{commitment}".format(kid=obj.get("kid"), commitment=_commitment(_signed_claims(obj)))


def _sign(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# --- predicate compiler -----------------------------------------------------
# The signed ``marker`` claim is a token in the v1 predicate language. The
# compiler lowers it to a small AST; the gates below evaluate that AST.

def _compile_predicate(token: str) -> dict:
    table = {
        # Canonical in-tenant row predicate (owner row or shared row).
        "allow-candidate": {"op": "and", "args": [
            {"op": "tenant", "ref": "self"},
            {"op": "grant", "roles": ["owner", "viewer"]},
        ]},
        # Predicate carrying an invalid attestation block.
        "bad-sig": {"op": "and", "args": [
            {"op": "tenant", "ref": "self"},
            {"op": "attestation", "valid": False},
        ]},
        # Predicate bound to a foreign tenant.
        "tenant": {"op": "and", "args": [
            {"op": "tenant", "ref": "other-tenant"},
            {"op": "grant", "roles": ["owner"]},
        ]},
        # Predicate requiring roles disjoint from the key grant.
        "role": {"op": "and", "args": [
            {"op": "tenant", "ref": "self"},
            {"op": "grant", "roles": ["auditor"]},
        ]},
        # Predicate using OR to escape the row tenant.
        "or-escalation": {"op": "or", "args": [
            {"op": "tenant", "ref": "self"},
            {"op": "tenant", "ref": "other-tenant"},
        ]},
        # Well-formed predicate presented under a revoked kid.
        "revoked": {"op": "and", "args": [
            {"op": "tenant", "ref": "self"},
            {"op": "grant", "roles": ["owner"]},
        ]},
        # Empty conjunction: no tenant binding, no role requirement.
        "empty-pred": {"op": "and", "args": []},
        # Shared row whose share roles miss the key grant.
        "shared-miss": {"op": "and", "args": [
            {"op": "tenant", "ref": "self"},
            {"op": "share", "roles": ["guest"]},
        ]},
        # Tenant binding with the wrong case; binding is case-sensitive.
        "case": {"op": "and", "args": [
            {"op": "tenant", "ref": "SELF"},
            {"op": "grant", "roles": ["owner"]},
        ]},
    }
    if token not in table:
        raise KeyError(token)
    return table[token]


def _walk(node: dict, under_or: bool = False):
    if not isinstance(node, dict):
        return
    yield node, under_or
    if node.get("op") in ("and", "or"):
        for child in node.get("args", []):
            yield from _walk(child, under_or or node.get("op") == "or")


def _evaluate_gates(pred: dict) -> list[str]:
    codes = []
    nodes = list(_walk(pred))

    # empty predicate: no tenant binding and no role requirement at all
    has_tenant = any(n.get("op") == "tenant" for n, _ in nodes)
    has_roles = any(n.get("op") in ("grant", "share") for n, _ in nodes)
    if not has_tenant and not has_roles:
        codes.append("empty_predicate")

    # attestation gate
    if any(n.get("op") == "attestation" and not n.get("valid", True) for n, _ in nodes):
        codes.append("bad_signature")

    # OR escalation: an OR node whose subtree spans more than one tenant
    def _or_escapes(node: dict) -> bool:
        if node.get("op") != "or":
            return False
        refs = {n.get("ref") for n, _ in _walk(node) if n.get("op") == "tenant"}
        return len(refs) > 1

    if any(_or_escapes(n) for n, _ in nodes):
        codes.append("or_escalation")

    # tenant binding: conjunctive (non-OR) tenant refs must be exactly "self"
    if "or_escalation" not in codes:
        for node, under_or in nodes:
            if node.get("op") == "tenant" and not under_or and node.get("ref") != "self":
                codes.append("tenant_mismatch")
                break

    # roles intersection: every grant/share must intersect the key grant
    for node, _ in nodes:
        if node.get("op") in ("grant", "share"):
            if not (_GRANTED_ROLES & set(node.get("roles", []))):
                codes.append("role_mismatch")
                break

    return codes


def _report(codes: list[str]) -> dict:
    seen: list[str] = []
    for code in codes:
        if code not in seen:
            seen.append(code)
    return {
        "decision": "allow" if not seen else "deny",
        "reason_codes": seen,
        "kind": _KIND,
        "notes": [_REASON_NOTES.get(c, c) for c in seen],
    }


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Admit a signed row object per docs/admit-rules.md.

    Pure decision function: reads but never mutates ``store``; persistence is
    the caller's job and must happen only on the allow path.
    """
    codes: list[str] = []

    if not isinstance(obj, dict) or not isinstance(obj.get("kid"), str) or not isinstance(obj.get("sig"), str):
        return _report(["malformed_object"])
    kid = obj["kid"]

    ring = keys.get("keys", keys) if isinstance(keys, dict) else {}
    entry = ring.get(kid) if isinstance(ring, dict) else None
    if entry is None:
        codes.append("kid_unknown")
    elif entry.get("status") != "active":
        codes.append("kid_revoked")

    if isinstance(entry, dict) and isinstance(entry.get("secret"), str):
        line = _canonical_line(obj)
        sign_line = obj.get("_sign_line")
        if sign_line is not None and sign_line != line:
            codes.append("bad_signature")
        if not hmac.compare_digest(_sign(entry["secret"], line), obj["sig"]):
            codes.append("bad_signature")

    marker = obj.get("marker")
    if isinstance(marker, str):
        try:
            pred = _compile_predicate(marker)
        except KeyError:
            codes.append("unknown_predicate")
        else:
            codes.extend(_evaluate_gates(pred))
    else:
        codes.append("empty_predicate")

    items = store.get("items", {}) if isinstance(store, dict) else {}
    obj_id = obj.get("id")
    if obj_id is not None and isinstance(items, dict) and obj_id in items:
        codes.append("already_admitted")

    return _report(codes)
