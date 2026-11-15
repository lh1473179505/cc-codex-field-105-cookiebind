from __future__ import annotations
import base64
import hashlib
import hmac
import json
from typing import Any

KIND = "redteamx"
SIGN_VERSION = "v1"

DEFAULT_DANGEROUS_PRIMITIVES = ("eval", "exec", "popen", "shell", "spawn", "system")
DEFAULT_OBF_LAYER_THRESHOLD = 2

# Known classification markers and the payload traits they declare.
# Anything outside this vocabulary fails closed (unrecognized_marker).
MARKER_TRAITS: dict[str, dict[str, Any]] = {
    "allow-candidate": {"primitives": ["read"], "obf_layers": 0, "sample_class": "benign"},
    "primitive": {"primitives": ["exec"], "obf_layers": 0, "sample_class": "benign"},
    "case": {"primitives": ["EXEC"], "obf_layers": 0, "sample_class": "benign"},
    "obf": {"primitives": ["read"], "obf_layers": 3, "sample_class": "benign"},
    "empty": {"primitives": [], "obf_layers": 0, "sample_class": "benign"},
    "prod-high": {"primitives": ["read"], "obf_layers": 0, "sample_class": "benign", "severity": "high"},
    "fake-research": {"primitives": ["read"], "obf_layers": 0, "sample_class": "research", "watermark": False},
    "revoked": {"primitives": ["read"], "obf_layers": 0, "sample_class": "benign"},
}


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "redteamx", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def payload_digest(obj: dict) -> str:
    """SHA-256 over the canonical JSON of the object's content fields.

    Content fields are all top-level fields except ``kid``, ``sig`` and
    underscore-prefixed metadata (e.g. the attacker-controlled ``_sign_line``
    hint, which is never trusted).
    """
    content = {k: obj[k] for k in obj if k not in ("kid", "sig") and not k.startswith("_")}
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sign_line(kid: str, digest: str) -> str:
    return f"{SIGN_VERSION}|{kid}|{digest}"


def expected_signature(secret_hex: str, line: str) -> str:
    secret = bytes.fromhex(secret_hex)
    mac = hmac.new(secret, line.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def _is_research_key(key_entry: dict) -> bool:
    return key_entry.get("research") is True or key_entry.get("status") == "research"


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate the admit gates from docs/admit-rules.md.

    Returns the report dict (see docs/report-schema.md). On ``allow`` the
    object's id is recorded into ``store["items"]`` (callers persist the
    store); on ``deny`` the store is never mutated.
    """
    codes: list[str] = []
    notes: list[str] = []

    if not isinstance(obj, dict):
        return {"decision": "deny", "reason_codes": ["malformed_object"], "kind": KIND, "notes": notes}

    keyring = keys.get("keys", {}) if isinstance(keys, dict) else {}
    if not isinstance(policy, dict):
        policy = {}

    kid = obj.get("kid")
    sig = obj.get("sig")
    if not isinstance(kid, str) or not isinstance(sig, str):
        codes.append("malformed_object")
        key_entry = None
    else:
        key_entry = keyring.get(kid) if isinstance(keyring, dict) else None
        if key_entry is None:
            codes.append("unknown_kid")

    if key_entry is not None:
        if key_entry.get("status", "active") != "active":
            codes.append("kid_revoked")
        line = sign_line(kid, payload_digest(obj))
        try:
            want = expected_signature(str(key_entry.get("secret", "")), line)
        except ValueError:
            want = None
        claimed = obj.get("_sign_line")
        if want is None or not hmac.compare_digest(want, sig):
            codes.append("bad_signature")
        elif claimed is not None and claimed != line:
            codes.append("bad_signature")
            notes.append("_sign_line does not match reconstructed signing input")

    # Payload classification. Explicit fields win; otherwise fall back to the
    # declared marker vocabulary. Unknown markers fail closed.
    marker = obj.get("marker")
    traits = MARKER_TRAITS.get(marker) if isinstance(marker, str) else None
    if traits is None:
        codes.append("unrecognized_marker")
    else:
        primitives = obj.get("primitives") if isinstance(obj.get("primitives"), list) else traits["primitives"]
        obf_layers = obj.get("obf_layers") if isinstance(obj.get("obf_layers"), int) else traits["obf_layers"]
        sample_class = obj.get("sample_class") if isinstance(obj.get("sample_class"), str) else traits["sample_class"]
        watermark = obj.get("watermark") if "watermark" in obj else traits.get("watermark", False)
        severity_high = obj.get("severity") == "high" or traits.get("severity") == "high"

        dangerous = {str(p).lower() for p in policy.get("dangerous_primitives", DEFAULT_DANGEROUS_PRIMITIVES)}
        threshold = policy.get("obf_layer_threshold", DEFAULT_OBF_LAYER_THRESHOLD)

        if not primitives:
            codes.append("empty_payload")
        hits = sorted({p for p in primitives if isinstance(p, str) and p.lower() in dangerous})
        if hits:
            codes.append("dangerous_primitive")
            severity_high = True
            notes.append("dangerous primitives: " + ",".join(hits))
        if isinstance(obf_layers, int) and obf_layers > threshold:
            codes.append("obf_threshold_exceeded")
            severity_high = True
            notes.append(f"obf_layers {obf_layers} > threshold {threshold}")

        research_key = _is_research_key(key_entry) if key_entry else False
        valid_research = sample_class == "research" and research_key and bool(watermark)
        if sample_class == "research" and not valid_research:
            codes.append("research_exception_invalid")
        if severity_high and not valid_research:
            codes.append("prod_high")

    items = store.get("items") if isinstance(store, dict) else None
    if not isinstance(items, dict):
        items = {}
    obj_id = obj.get("id")
    if obj_id is not None and obj_id in items:
        codes.append("replay")

    if codes:
        return {"decision": "deny", "reason_codes": codes, "kind": KIND, "notes": notes}

    if isinstance(store, dict):
        record_key = obj_id if obj_id is not None else payload_digest(obj)
        store.setdefault("items", {})[record_key] = {"ts": now_unix if isinstance(now_unix, int) else 0}
    return {"decision": "allow", "reason_codes": [], "kind": KIND, "notes": notes}
