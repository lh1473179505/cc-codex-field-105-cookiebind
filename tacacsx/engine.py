from __future__ import annotations
import base64
import hashlib
import hmac

SIGNING_VERSION = "v1"

_STRING_FIELDS = ("kid", "user", "group", "service", "command", "nonce", "sig")
_REQUIRED_FIELDS = _STRING_FIELDS + ("args", "priv_lvl", "iat")

def inspect_command(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "group": obj.get("group"),
        "service": obj.get("service"),
        "command": obj.get("command"),
        "args": obj.get("args"),
        "priv_lvl": obj.get("priv_lvl"),
        "nonce": obj.get("nonce"),
    }

def admit_command(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    command = obj.get("command") if isinstance(obj, dict) else None

    if not _well_formed(obj):
        return _deny(command, "malformed_command")

    key_entries = keys.get("keys") if isinstance(keys, dict) else None
    if not isinstance(key_entries, dict):
        return _deny(command, "malformed_keys")
    key = key_entries.get(obj["kid"])
    if not isinstance(key, dict) or not isinstance(key.get("secret"), str):
        return _deny(command, "unknown_kid")
    if key.get("status") != "active":
        return _deny(command, "key_revoked")
    try:
        secret = bytes.fromhex(key["secret"])
    except ValueError:
        return _deny(command, "malformed_keys")

    signing_line = _signing_line(obj).encode("utf-8")
    digest = hmac.new(secret, signing_line, hashlib.sha256).digest()
    expected_sig = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(expected_sig, obj["sig"]):
        return _deny(command, "bad_signature")

    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    age = now_unix - obj["iat"]
    if age > max_age or age < -skew:
        return _deny(command, "iat_outside_window")

    items = store.setdefault("items", {})
    if obj["nonce"] in items:
        return _deny(command, "nonce_replay")

    groups = policy.get("groups")
    if not isinstance(groups, dict):
        return _deny(command, "malformed_policy")
    group = groups.get(obj["group"])
    if not isinstance(group, dict):
        return _deny(command, "unknown_group")

    members = group.get("users")
    if not isinstance(members, list) or obj["user"] not in members:
        return _deny(command, "user_not_in_group")

    services = group.get("services")
    if not isinstance(services, dict):
        return _deny(command, "unknown_service")
    service = services.get(obj["service"])
    if not isinstance(service, dict):
        return _deny(command, "unknown_service")

    commands = service.get("commands")
    if not isinstance(commands, dict):
        return _deny(command, "unknown_command")
    command_policy = commands.get(obj["command"])
    if not isinstance(command_policy, dict):
        return _deny(command, "unknown_command")

    argument_sets = command_policy.get("argument_sets")
    if not isinstance(argument_sets, list) or obj["args"] not in argument_sets:
        return _deny(command, "args_mismatch")

    priv_lvls = command_policy.get("priv_lvls")
    if not isinstance(priv_lvls, list) or obj["priv_lvl"] not in priv_lvls:
        return _deny(command, "priv_lvl_denied")

    items[obj["nonce"]] = {"ts": obj["iat"]}
    return {"decision": "allow", "reason_codes": [], "command": obj["command"]}


def _deny(command, reason_code: str) -> dict:
    return {"decision": "deny", "reason_codes": [reason_code], "command": command}


def _well_formed(obj) -> bool:
    if not isinstance(obj, dict):
        return False
    if any(field not in obj for field in _REQUIRED_FIELDS):
        return False
    if any(not isinstance(obj[field], str) for field in _STRING_FIELDS):
        return False
    if not isinstance(obj["args"], list):
        return False
    if any(not isinstance(item, str) for item in obj["args"]):
        return False
    if isinstance(obj["priv_lvl"], bool) or not isinstance(obj["priv_lvl"], int):
        return False
    if isinstance(obj["iat"], bool) or not isinstance(obj["iat"], int):
        return False
    return True


def _signing_line(obj: dict) -> str:
    return "|".join((
        SIGNING_VERSION,
        obj["kid"],
        obj["user"],
        obj["group"],
        obj["service"],
        obj["command"],
        ",".join(obj["args"]),
        str(obj["priv_lvl"]),
        str(obj["iat"]),
        obj["nonce"],
    ))
