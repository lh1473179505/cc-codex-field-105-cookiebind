from __future__ import annotations
import base64
import hashlib
import hmac
import re
from typing import Any

def inspect_request(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "resource": obj.get("resource"),
        "role": obj.get("role"),
        "duration": obj.get("duration"),
        "ticket": obj.get("ticket"),
        "approval": obj.get("approval"),
        "nonce": obj.get("nonce"),
    }

def _deny(obj: dict, code: str) -> dict:
    return {"decision": "deny", "reason_codes": [code], "resource": obj.get("resource")}

def _signing_input(obj: dict) -> str:
    approval = obj.get("approval") or {}
    rendered = ",".join(f"{key}={approval[key]}" for key in sorted(approval))
    return "|".join([
        "v1",
        str(obj.get("kid")),
        str(obj.get("user")),
        str(obj.get("resource")),
        str(obj.get("role")),
        str(obj.get("duration")),
        str(obj.get("ticket")),
        rendered,
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ])

def admit_request(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    user = obj.get("user")
    resource = obj.get("resource")
    role = obj.get("role")

    users = policy.get("users", {})
    if user not in users:
        return _deny(obj, "unknown_user")

    resources = policy.get("resources", {})
    if resource not in resources:
        return _deny(obj, "unknown_resource")

    if resource not in users.get(user, []):
        return _deny(obj, "resource_not_authorized")

    roles = resources[resource].get("roles", {})
    if role not in roles:
        return _deny(obj, "unknown_role")
    role_policy = roles[role]

    duration = obj.get("duration")
    if not isinstance(duration, int) or isinstance(duration, bool):
        return _deny(obj, "bad_duration")
    if duration < role_policy.get("duration_min"):
        return _deny(obj, "duration_too_low")
    if duration > role_policy.get("duration_max"):
        return _deny(obj, "duration_too_high")

    ticket = obj.get("ticket")
    if not isinstance(ticket, str) or re.fullmatch(policy.get("ticket_pattern", ""), ticket) is None:
        return _deny(obj, "bad_ticket_syntax")
    if not ticket.startswith(role_policy.get("ticket_prefix", "")):
        return _deny(obj, "bad_ticket_prefix")

    approval = obj.get("approval")
    if not isinstance(approval, dict) or set(approval.keys()) != {"approver", "decision"}:
        return _deny(obj, "invalid_approval")
    if approval.get("approver") not in role_policy.get("approvers", []):
        return _deny(obj, "bad_approver")
    if approval.get("decision") not in policy.get("approval_decisions", []):
        return _deny(obj, "bad_decision")
    if policy.get("forbid_self_approval") and approval.get("approver") == user:
        return _deny(obj, "self_approval")

    key_bag = keys.get("keys", {})
    key = key_bag.get(obj.get("kid"))
    if not isinstance(key, dict):
        return _deny(obj, "unknown_key")
    if key.get("status") != "active":
        return _deny(obj, "key_revoked")

    secret = bytes.fromhex(key["secret"])
    digest = hmac.new(secret, _signing_input(obj).encode("utf-8"), hashlib.sha256).digest()
    signature = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    provided = obj.get("sig")
    if not isinstance(provided, str) or not hmac.compare_digest(signature, provided):
        return _deny(obj, "bad_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        return _deny(obj, "bad_iat")
    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if now_unix - iat > max_age:
        return _deny(obj, "stale_iat")
    if iat - now_unix > skew:
        return _deny(obj, "future_iat")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if nonce in items:
        return _deny(obj, "replay_nonce")

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "resource": resource}
