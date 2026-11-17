from __future__ import annotations
import base64
import hashlib
import hmac
import re
from typing import Any

_MODULE_RE = re.compile(r"[a-z][a-z0-9_-]*\Z")
_HEX_RE = re.compile(r"[0-9a-f]*\Z")


def inspect_module(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "module": obj.get("module"),
        "path": obj.get("path"),
        "digest": obj.get("digest"),
        "sig_alg": obj.get("sig_alg"),
        "keyring": obj.get("keyring"),
        "params": obj.get("params"),
        "nonce": obj.get("nonce"),
    }


def _params_line(params: dict) -> str:
    return ",".join(f"{k}={params[k]}" for k in sorted(params))


def _signing_line(kid, module, path, digest, sig_alg, keyring, params, iat, nonce) -> str:
    return "|".join([
        "v1", kid, module, path, digest, sig_alg, keyring,
        _params_line(params), str(iat), nonce,
    ])


def _b64url_decode(sig: str) -> bytes:
    pad = "=" * (-len(sig) % 4)
    return base64.urlsafe_b64decode(sig + pad)


def _path_is_canonical(path: str, deny_substrings: list) -> bool:
    if not path.startswith("/"):
        return False
    for sub in deny_substrings:
        if sub and sub in path:
            return False
    for comp in path.split("/")[1:]:
        if comp in ("", ".", ".."):
            return False
    return True


def admit_module(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    module = obj.get("module")

    if not isinstance(module, str) or not _MODULE_RE.fullmatch(module):
        reasons.append("module_syntax")
        mod_policy = None
    else:
        mod_policy = policy.get("modules", {}).get(module)
        if mod_policy is None:
            reasons.append("module_unknown")

    path = obj.get("path")
    deny_substrings = policy.get("path_deny_substrings", [])
    if not isinstance(path, str) or not _path_is_canonical(path, deny_substrings):
        reasons.append("path_syntax")
    elif mod_policy is not None and path != mod_policy.get("path"):
        reasons.append("path_binding")

    digest = obj.get("digest")
    hex_len = policy.get("digest_hex_len", 64)
    if not isinstance(digest, str) or len(digest) != hex_len or not _HEX_RE.fullmatch(digest):
        reasons.append("digest_syntax")
    elif mod_policy is not None and digest != mod_policy.get("digest"):
        reasons.append("digest_binding")

    sig_alg = obj.get("sig_alg")
    if mod_policy is not None and sig_alg not in mod_policy.get("sig_algs", []):
        reasons.append("sig_alg")

    keyring = obj.get("keyring")
    if mod_policy is not None and keyring != mod_policy.get("keyring"):
        reasons.append("keyring")

    params = obj.get("params")
    params_ok = isinstance(params, dict) and all(
        isinstance(k, str) and isinstance(v, str) for k, v in params.items()
    )
    if not params_ok:
        reasons.append("params_syntax")
        params = {}
    if mod_policy is not None:
        allowed = set(mod_policy.get("params_allowed", []))
        required = mod_policy.get("params_required", {})
        values = mod_policy.get("param_values", {})
        if any(k not in allowed for k in params):
            reasons.append("param_extra")
        if any(params.get(k) != v for k, v in required.items()):
            reasons.append("param_required")
        if any(k in values and params[k] not in values[k] for k in params):
            reasons.append("param_value")

    kid = obj.get("kid")
    key_entry = keys.get("keys", {}).get(kid) if isinstance(kid, str) else None
    if key_entry is None:
        reasons.append("key_unknown")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("iat_syntax")
        iat = None
    else:
        skew = policy.get("clock_skew_seconds", 0)
        max_age = policy.get("max_age_seconds", 0)
        if iat > now_unix + skew or iat < now_unix - max_age:
            reasons.append("iat_window")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_syntax")
        nonce = None

    sig = obj.get("sig")
    if key_entry is not None and iat is not None and nonce is not None:
        if not isinstance(sig, str):
            reasons.append("bad_sig")
        else:
            line = _signing_line(
                kid, module if isinstance(module, str) else "",
                path if isinstance(path, str) else "",
                digest if isinstance(digest, str) else "",
                sig_alg if isinstance(sig_alg, str) else "",
                keyring if isinstance(keyring, str) else "",
                params, iat, nonce,
            )
            secret = bytes.fromhex(key_entry["secret"])
            expected = hmac.new(secret, line.encode("utf-8"), hashlib.sha256).digest()
            try:
                provided = _b64url_decode(sig)
            except Exception:
                provided = b""
            if not hmac.compare_digest(expected, provided):
                reasons.append("bad_sig")

    if nonce is not None and nonce in store.get("items", {}):
        reasons.append("replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "module": module}

    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "module": module}
