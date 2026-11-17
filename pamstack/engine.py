from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_entry(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "service": obj.get("service"),
        "module": obj.get("module"),
        "control": obj.get("control"),
        "arguments": obj.get("arguments"),
        "order": obj.get("order"),
        "nonce": obj.get("nonce"),
    }

def _deny(service: Any, code: str) -> dict:
    return {"decision": "deny", "reason_codes": [code], "service": service}

def _arguments_line(arguments: Any) -> str:
    if not isinstance(arguments, dict):
        raise TypeError("arguments")
    return ",".join(f"{key}={arguments[key]}" for key in sorted(arguments))

def _signing_line(obj: dict) -> str:
    return "|".join([
        "v1",
        str(obj["kid"]),
        str(obj["service"]),
        str(obj["module"]),
        str(obj["control"]),
        _arguments_line(obj["arguments"]),
        str(obj["order"]),
        str(obj["iat"]),
        str(obj["nonce"]),
    ])

def _expected_signature(secret: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

def _terminal_deny_ok(services: dict) -> bool:
    for conf in services.values():
        stack = conf.get("stack")
        if not isinstance(stack, list) or not stack:
            return False
        terminal = stack[-1]
        if not isinstance(terminal, dict):
            return False
        if terminal.get("module") != "pam_deny.so" or terminal.get("control") != "required":
            return False
        if terminal.get("arguments") != {}:
            return False
    return True

def admit_entry(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    service = obj.get("service")
    try:
        line = _signing_line(obj)
    except (KeyError, TypeError):
        return _deny(service, "bad_shape")

    key = keys.get("keys", {}).get(obj.get("kid"))
    if not isinstance(key, dict) or "secret" not in key:
        return _deny(service, "bad_sig")
    try:
        expected = _expected_signature(key["secret"], line)
    except ValueError:
        return _deny(service, "bad_sig")
    submitted = obj.get("sig")
    if not isinstance(submitted, str) or not hmac.compare_digest(expected, submitted):
        return _deny(service, "bad_sig")

    if key.get("status") != "active":
        return _deny(service, "revoked")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        return _deny(service, "clock_skew")
    delta = now_unix - iat
    if delta < -policy.get("clock_skew_seconds", 0):
        return _deny(service, "clock_skew")
    if delta > policy.get("max_age_seconds", 0) or delta > policy.get("clock_skew_seconds", 0):
        return _deny(service, "max_age")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return _deny(service, "nonce_missing")
    if nonce in store.get("items", {}):
        return _deny(service, "replay")

    services = policy.get("services", {})
    conf = services.get(service)
    if not isinstance(conf, dict):
        return _deny(service, "service")
    stack = conf.get("stack")
    if not isinstance(stack, list):
        return _deny(service, "service")

    module = obj.get("module")
    if not isinstance(module, str) or not module:
        return _deny(service, "module")
    if policy.get("forbid_module_paths", False) and ("/" in module or "\\" in module):
        return _deny(service, "module_path")
    if module in policy.get("forbidden_modules", []):
        return _deny(service, "forbidden_module")

    order = obj.get("order")
    if not isinstance(order, int) or isinstance(order, bool) or not 0 <= order < len(stack):
        return _deny(service, "order_range")

    entry = stack[order]
    arguments = obj.get("arguments")
    if module != entry.get("module"):
        if any((module, obj.get("control"), arguments) ==
               (item.get("module"), item.get("control"), item.get("arguments"))
               for item in stack):
            return _deny(service, "order_skip")
        return _deny(service, "module")
    if obj.get("control") != entry.get("control"):
        return _deny(service, "control")
    if not isinstance(arguments, dict):
        return _deny(service, "argument_required")
    required = entry.get("arguments", {})
    if set(arguments) != set(required):
        if set(arguments) < set(required):
            return _deny(service, "argument_required")
        return _deny(service, "argument_extra")
    if arguments != required:
        return _deny(service, "argument_value")

    if policy.get("require_terminal_deny", False) and not _terminal_deny_ok(services):
        return _deny(service, "terminal_deny")

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "service": service}
