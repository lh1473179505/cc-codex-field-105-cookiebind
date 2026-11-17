from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_binding(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "project": obj.get("project"),
        "role": obj.get("role"),
        "principal": obj.get("principal"),
        "condition": obj.get("condition"),
        "nonce": obj.get("nonce"),
    }

_PRINCIPAL_SCHEMES = ("user", "group", "serviceAccount")

def _condition_string(condition: dict) -> str:
    return ",".join(f"{k}={v}" for k, v in sorted(condition.items()))

def _signature_line(obj: dict) -> str:
    return "v1|{kid}|{project}|{role}|{principal}|{condition}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        project=obj.get("project"),
        role=obj.get("role"),
        principal=obj.get("principal"),
        condition=_condition_string(obj.get("condition") or {}),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _check_principal(principal: Any, proj: dict, reasons: list) -> None:
    if not isinstance(principal, str) or ":" not in principal:
        reasons.append("principal_shape")
        return
    scheme, _, mailbox = principal.partition(":")
    if scheme not in _PRINCIPAL_SCHEMES or "@" not in mailbox:
        reasons.append("principal_shape")
        return
    name, _, domain = mailbox.rpartition("@")
    if not name or not domain:
        reasons.append("principal_shape")
        return
    if scheme in ("user", "group"):
        if domain not in proj.get("member_domains", []):
            reasons.append("principal_domain")
    else:
        suffix = ".iam.gserviceaccount.com"
        sa_project = domain[:-len(suffix)] if domain.endswith(suffix) else None
        if not sa_project or sa_project not in proj.get("service_account_projects", []):
            reasons.append("service_account_project")

def _check_condition(condition: Any, role: Any, proj: dict, reasons: list) -> None:
    if not isinstance(condition, dict):
        reasons.append("condition_shape")
        return
    required = role in proj.get("required_condition_roles", [])
    must_be_empty = role in proj.get("empty_condition_roles", [])
    if not condition:
        if required:
            reasons.append("condition_required")
        return
    if must_be_empty:
        reasons.append("condition_unexpected")
        return
    if set(condition.keys()) != {"title", "expression"}:
        reasons.append("condition_shape")
        return
    conditions = proj.get("conditions", {})
    title = condition["title"]
    if title not in conditions:
        reasons.append("condition_title")
        return
    if condition["expression"] != conditions[title]:
        reasons.append("condition_expression")

def admit_binding(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list = []
    project = obj.get("project") if isinstance(obj, dict) else None

    key_entry = keys.get("keys", {}).get(obj.get("kid")) if isinstance(obj, dict) else None
    if key_entry is None:
        reasons.append("key_unknown")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")

    proj = policy.get("projects", {}).get(project)
    if proj is None:
        reasons.append("project_not_allowed")
        proj = {}

    role = obj.get("role")
    if policy.get("forbid_owner") and role == "roles/owner":
        reasons.append("owner_forbidden")
    if role not in proj.get("roles", []):
        reasons.append("role_not_allowed")

    principal = obj.get("principal")
    if principal in policy.get("forbid_public_principals", []):
        reasons.append("public_principal")
    else:
        _check_principal(principal, proj, reasons)
        if isinstance(principal, str) and ":" in principal:
            scheme = principal.partition(":")[0]
            allowed = proj.get("role_principals", {}).get(role, [])
            if scheme in _PRINCIPAL_SCHEMES and scheme not in allowed:
                reasons.append("role_principal_not_allowed")

    _check_condition(obj.get("condition"), role, proj, reasons)

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("iat_shape")
    else:
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            reasons.append("iat_future")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("iat_stale")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_shape")
    elif nonce in store.get("items", {}):
        reasons.append("nonce_replay")

    if key_entry is not None:
        try:
            secret = bytes.fromhex(key_entry.get("secret", ""))
        except ValueError:
            secret = key_entry.get("secret", "").encode()
        digest = hmac.new(secret, _signature_line(obj).encode(), hashlib.sha256).digest()
        expected = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            reasons.append("bad_signature")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "project": project}

    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "project": project}
