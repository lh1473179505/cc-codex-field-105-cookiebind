from __future__ import annotations
import base64
import hashlib
import hmac
import json
from typing import Any

_EXCLUDED_CONTENT_KEYS = {"kid", "sig"}
_ALLOW_MARKER = "allow-candidate"
_MARKER_REASON_ALIASES = {"revoked": "kid_revoked"}


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "sandtrap", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def _signed_content(obj: dict) -> dict:
    return {
        k: v
        for k, v in obj.items()
        if k not in _EXCLUDED_CONTENT_KEYS and not k.startswith("_")
    }


def _trace_sha(content: dict) -> str:
    blob = json.dumps(content, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _csv(value: Any) -> str:
    if not value:
        return ""
    return ",".join(str(v) for v in value)


def _sign_line(obj: dict, content: dict) -> str:
    line = f"v1|{obj.get('kid', '')}|{_trace_sha(content)}"
    required_csv = _csv(obj.get("required"))
    denied_csv = _csv(obj.get("denied"))
    if required_csv or denied_csv:
        line = f"{line}|{required_csv}|{denied_csv}"
    return line


def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(
        bytes.fromhex(secret_hex), line.encode("ascii"), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _event_name(event: Any) -> str:
    if isinstance(event, dict):
        return str(event.get("name", ""))
    return str(event)


def _trace_reasons(obj: dict) -> list[str]:
    reasons: list[str] = []
    trace = obj.get("trace") or []
    names = [_event_name(e) for e in trace]
    required = [str(r) for r in (obj.get("required") or [])]
    denied = [str(d) for d in (obj.get("denied") or [])]
    if required and not trace:
        reasons.append("empty_trace")
    if any(r not in names for r in required):
        reasons.append("required_missing")
    elif required:
        start = 0
        for name in required:
            found = -1
            for i in range(start, len(names)):
                if names[i] == name:
                    found = i
                    break
            if found < 0:
                reasons.append("order_violation")
                break
            start = found + 1
    if any(d in names for d in denied):
        reasons.append("denied_call")
    arg_reqs = obj.get("args") or {}
    for call, expected in arg_reqs.items():
        matched = False
        for event in trace:
            if isinstance(event, dict) and event.get("name") == call:
                event_args = event.get("args") or {}
                if all(event_args.get(k) == v for k, v in expected.items()):
                    matched = True
                    break
        if not matched:
            reasons.append("arg_mismatch")
            break
    return reasons


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Admit or deny a signed request per docs/admit-rules.md.

    On allow the request id is recorded into ``store["items"]``; on deny the
    store is left untouched.
    """
    reasons: list[str] = []
    content = _signed_content(obj)
    keyring = keys.get("keys", keys) if isinstance(keys, dict) else {}
    key_entry = keyring.get(obj.get("kid")) if isinstance(keyring, dict) else None
    if key_entry is None:
        reasons.append("unknown_kid")
    else:
        line = _sign_line(obj, content)
        expected = _expected_sig(str(key_entry.get("secret", "")), line)
        if not hmac.compare_digest(expected, str(obj.get("sig", ""))):
            reasons.append("sig_invalid")
        if key_entry.get("status") != "active":
            reasons.append("kid_revoked")
    if isinstance(policy, dict) and not policy.get("allowed", True):
        reasons.append("policy_denied")
    items = store.get("items") if isinstance(store, dict) else None
    if not isinstance(items, dict):
        raise ValueError("store must be object with items object")
    request_id = obj.get("id")
    if request_id is not None and request_id in items:
        reasons.append("replay")
    reasons.extend(_trace_reasons(obj))
    marker = content.get("marker")
    if marker != _ALLOW_MARKER:
        code = str(marker).replace("-", "_") if marker else "marker_missing"
        code = _MARKER_REASON_ALIASES.get(code, code)
        if code not in reasons:
            reasons.append(code)
    decision = "deny" if reasons else "allow"
    if decision == "allow" and request_id is not None:
        items[request_id] = {"ts": now_unix}
    return {
        "decision": decision,
        "reason_codes": reasons,
        "kind": str(policy.get("pkg", "sandtrap")) if isinstance(policy, dict) else "sandtrap",
        "notes": [],
    }
