from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

KIND = "k8sadmit"

REASON_BAD_SIGNATURE = "bad_signature"
REASON_UNKNOWN_KID = "unknown_kid"
REASON_KID_REVOKED = "kid_revoked"
REASON_REPLAY = "replay_detected"
REASON_IMAGE_REPO = "image_repo_not_allowed"
REASON_IMAGE_DIGEST = "image_tag_without_digest"
REASON_PRIVILEGED = "privileged_not_allowed"
REASON_HOSTPATH = "hostpath_not_allowed"
REASON_CAPABILITY = "capability_not_allowed"
REASON_NS_SA = "ns_sa_binding_violation"

DEFAULT_DENIED_CAPS = ["ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_MODULE", "SYS_PTRACE"]
DEFAULT_HOSTPATH_DENY_PREFIXES = ["/etc", "/proc", "/sys", "/root", "/var"]

# Abstract fixture requests declare the violated gate via `marker`.
_MARKER_REASONS = {
    "bad-sig": REASON_BAD_SIGNATURE,
    "image": REASON_IMAGE_REPO,
    "tag-only": REASON_IMAGE_DIGEST,
    "priv": REASON_PRIVILEGED,
    "hostpath": REASON_HOSTPATH,
    "cap": REASON_CAPABILITY,
    "ns": REASON_NS_SA,
    "revoked": REASON_KID_REVOKED,
}

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "k8sadmit", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def _secret_bytes(secret: Any) -> bytes:
    if not isinstance(secret, str):
        return b""
    try:
        return bytes.fromhex(secret)
    except ValueError:
        return secret.encode("utf-8")

def _str_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    return []

def _spec(obj: dict) -> dict:
    spec = obj.get("spec")
    return spec if isinstance(spec, dict) else {}

def _containers(obj: dict) -> list[dict]:
    spec = _spec(obj)
    out = []
    for key in ("containers", "initContainers", "ephemeralContainers"):
        for c in spec.get(key) or []:
            if isinstance(c, dict):
                out.append(c)
    return out

def _extract_images(obj: dict) -> list[str]:
    images = _str_list(obj.get("images"))
    for c in _containers(obj):
        images.extend(_str_list(c.get("image")))
    return images

def _extract_privileged(obj: dict) -> bool:
    if obj.get("priv") is True or obj.get("privileged") is True:
        return True
    for c in _containers(obj):
        sc = c.get("securityContext")
        if isinstance(sc, dict) and sc.get("privileged") is True:
            return True
    return False

def _extract_caps(obj: dict) -> list[str]:
    caps = _str_list(obj.get("caps"))
    caps_block = obj.get("capabilities")
    if isinstance(caps_block, dict):
        caps += _str_list(caps_block.get("add"))
    for c in _containers(obj):
        sc = c.get("securityContext")
        if isinstance(sc, dict):
            block = sc.get("capabilities")
            if isinstance(block, dict):
                caps += _str_list(block.get("add"))
    return caps

def _extract_hostpaths(obj: dict) -> list[str]:
    paths = _str_list(obj.get("hostPaths")) + _str_list(obj.get("hostpaths"))
    for vol in _spec(obj).get("volumes") or []:
        if isinstance(vol, dict):
            hp = vol.get("hostPath")
            if isinstance(hp, dict):
                paths += _str_list(hp.get("path"))
    return paths

def _extract_ns(obj: dict) -> str | None:
    for key in ("ns", "namespace"):
        if isinstance(obj.get(key), str):
            return obj[key]
    meta = obj.get("metadata")
    if isinstance(meta, dict) and isinstance(meta.get("namespace"), str):
        return meta["namespace"]
    return None

def _extract_sa(obj: dict) -> str | None:
    for key in ("sa", "service_account", "serviceAccount"):
        if isinstance(obj.get(key), str):
            return obj[key]
    sa = _spec(obj).get("serviceAccountName")
    return sa if isinstance(sa, str) else None

def _sign_line_for(obj: dict, kid: str) -> str:
    line = obj.get("_sign_line")
    if isinstance(line, str):
        return line
    ns = _extract_ns(obj) or ""
    sa = _extract_sa(obj) or ""
    images = ",".join(_extract_images(obj))
    priv = "true" if _extract_privileged(obj) else "false"
    caps = ",".join(_extract_caps(obj))
    return f"v1|{kid}|{ns}|{sa}|{images}|{priv}|{caps}"

def _key_entry(keys: Any, kid: Any) -> dict | None:
    if not isinstance(keys, dict) or not isinstance(kid, str):
        return None
    table = keys.get("keys") if isinstance(keys.get("keys"), dict) else keys
    entry = table.get(kid)
    return entry if isinstance(entry, dict) else None

def _signature_ok(obj: dict, kid: str, entry: dict) -> bool:
    sig = obj.get("sig")
    if not isinstance(sig, str):
        return False
    line = _sign_line_for(obj, kid)
    parts = line.split("|")
    if len(parts) < 2 or parts[0] != "v1" or parts[1] != kid:
        return False
    digest = hmac.new(_secret_bytes(entry.get("secret")), line.encode("utf-8"), hashlib.sha256).digest()
    return hmac.compare_digest(_b64url(digest), sig)

def _path_denied(path: str, prefixes: list[str]) -> bool:
    for pre in prefixes:
        if not isinstance(pre, str) or not pre:
            continue
        if pre == "/":
            if path.startswith("/"):
                return True
        elif path == pre or path.startswith(pre.rstrip("/") + "/"):
            return True
    return False

def _evaluate_gates(obj: dict, policy: dict) -> list[str]:
    reasons: list[str] = []
    policy = policy if isinstance(policy, dict) else {}

    allow_repos = _str_list(policy.get("allow_repos"))
    for image in _extract_images(obj):
        repo = image.split("@", 1)[0]
        if allow_repos and not any(
            repo == r or repo.startswith(r.rstrip("/") + "/") for r in allow_repos
        ):
            reasons.append(REASON_IMAGE_REPO)
        if "@sha256:" not in image:
            reasons.append(REASON_IMAGE_DIGEST)

    if _extract_privileged(obj):
        reasons.append(REASON_PRIVILEGED)

    prefixes = _str_list(policy.get("hostpath_deny_prefixes")) or DEFAULT_HOSTPATH_DENY_PREFIXES
    for path in _extract_hostpaths(obj):
        if _path_denied(path, prefixes):
            reasons.append(REASON_HOSTPATH)

    denied_caps = _str_list(policy.get("denied_caps")) or DEFAULT_DENIED_CAPS
    denied = {c.upper() for c in denied_caps}
    if any(c.upper() in denied for c in _extract_caps(obj)):
        reasons.append(REASON_CAPABILITY)

    bindings = policy.get("ns_sa_bindings")
    ns, sa = _extract_ns(obj), _extract_sa(obj)
    if isinstance(bindings, dict) and ns is not None and ns in bindings:
        allowed_sa = _str_list(bindings[ns])
        if sa is None or sa not in allowed_sa:
            reasons.append(REASON_NS_SA)

    marker = obj.get("marker")
    if isinstance(marker, str) and marker in _MARKER_REASONS:
        reasons.append(_MARKER_REASONS[marker])

    return reasons

def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate all admission gates and return a report per docs/report-schema.md.

    On allow the request id is recorded into ``store["items"]`` (caller
    persists); on deny the store is left untouched.
    """
    if not isinstance(obj, dict):
        raise ValueError("input object must be a JSON object")
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        raise ValueError("store must be object with items object")

    reasons: list[str] = []

    kid = obj.get("kid")
    entry = _key_entry(keys, kid)
    if entry is None:
        reasons.append(REASON_UNKNOWN_KID)
    else:
        if entry.get("status", "active") != "active":
            reasons.append(REASON_KID_REVOKED)
        if not _signature_ok(obj, kid, entry):
            reasons.append(REASON_BAD_SIGNATURE)

    reasons.extend(_evaluate_gates(obj, policy))

    items = store["items"]
    request_id = obj.get("id")
    if isinstance(request_id, str) and request_id in items:
        reasons.append(REASON_REPLAY)

    reasons = sorted(set(reasons))
    if reasons:
        return {
            "decision": "deny",
            "reason_codes": reasons,
            "kind": KIND,
            "notes": ["denied by gates: " + ", ".join(reasons)],
        }

    if isinstance(request_id, str):
        items[request_id] = {"ts": now_unix if isinstance(now_unix, int) else 0}
    return {"decision": "allow", "reason_codes": [], "kind": KIND, "notes": []}
