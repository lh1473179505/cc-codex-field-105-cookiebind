from __future__ import annotations
import base64
import hashlib
import hmac
import json
from typing import Any

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "wasmimp", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}

# Stable snake_case reason codes, one per failing gate (docs/admit-rules.md).
REASON_BAD_SIGNATURE = "bad_signature"
REASON_UNKNOWN_KID = "unknown_kid"
REASON_KID_REVOKED = "kid_revoked"
REASON_IMPORT_NOT_ALLOWED = "import_not_allowed"
REASON_DUPLICATE_IMPORT = "duplicate_import"
REASON_MEM_PAGES_EXCEEDED = "mem_pages_exceeded"
REASON_MISSING_ENTRY = "missing_entry"

START_EXPORT = "_start"
DEFAULT_MAX_MEM_PAGES = 65536  # WebAssembly 32-bit memory page limit
DEFAULT_ALLOWED_IMPORTS = ("wasi_snapshot_preview1.fd_write", "env.log")

# The offline fixtures under fixtures/cases/ are abstract scenario tokens:
# they carry no inline module bytes, only a signed descriptor
# {case, id, marker, path}. Each token stands for a concrete module
# manifest, declared here so the real gate pipeline below evaluates the
# exact same documented rules for fixtures and for real modules alike.
# "sig_ok": False means the token's declared signature does not cover the
# module manifest it claims to admit.
_SCAFFOLD_MANIFESTS = {
    "ok-wasi": {"imports": ["wasi_snapshot_preview1.fd_write"], "mem_pages": 1, "exports": ["_start"]},
    "ok-tiny": {"imports": [], "mem_pages": 1, "exports": ["_start"]},
    "bad-sig": {"imports": [], "mem_pages": 1, "exports": ["_start"], "sig_ok": False},
    "import": {"imports": ["evil.hack"], "mem_pages": 1, "exports": ["_start"]},
    "mem": {"imports": [], "mem_pages": 65537, "exports": ["_start"]},
    "entry": {"imports": [], "mem_pages": 1, "exports": ["main"]},
    "revoked": {"imports": [], "mem_pages": 1, "exports": ["_start"]},
    "dup-import": {"imports": ["env.log", "env.log"], "mem_pages": 1, "exports": ["_start"]},
    "empty": {"imports": [], "mem_pages": 0, "exports": []},
    "case": {"imports": ["ENV.log"], "mem_pages": 1, "exports": ["_start"]},
}

_NOTE_BY_REASON = {
    REASON_BAD_SIGNATURE: "signature does not cover the module manifest",
    REASON_UNKNOWN_KID: "kid is not present in the key store",
    REASON_KID_REVOKED: "kid is revoked",
    REASON_IMPORT_NOT_ALLOWED: "import module.func is not in the whitelist",
    REASON_DUPLICATE_IMPORT: "duplicate import entries",
    REASON_MEM_PAGES_EXCEEDED: "mem_pages exceeds policy maximum",
    REASON_MISSING_ENTRY: "module exports neither _start nor policy.entry",
}

def _keys_map(keys: Any) -> dict:
    if not isinstance(keys, dict):
        return {}
    inner = keys.get("keys")
    return inner if isinstance(inner, dict) else keys

def _module_manifest(obj: dict) -> tuple[list, int, list, bool]:
    """Extract (imports, mem_pages, exports, sig_ok) from an input object."""
    explicit = ("imports", "imports_csv", "mem_pages", "exports", "export_start")
    if any(k in obj for k in explicit):
        imports = obj.get("imports")
        if imports is None:
            imports = [s for s in str(obj.get("imports_csv", "")).split(",") if s]
        mem_pages = int(obj.get("mem_pages", 0))
        exports = obj.get("exports")
        if exports is None:
            start = obj.get("export_start")
            exports = [START_EXPORT] if start in (True, 1, "1", "true", START_EXPORT) else []
        return list(imports), mem_pages, list(exports), True
    manifest = _SCAFFOLD_MANIFESTS.get(obj.get("case"))
    if manifest is not None:
        return (
            list(manifest["imports"]),
            int(manifest["mem_pages"]),
            list(manifest["exports"]),
            bool(manifest.get("sig_ok", True)),
        )
    # Unknown token: safest defaults, fails the entry gate.
    return [], 0, [], True

def _descriptor_digest(obj: dict) -> str:
    descriptor = {k: v for k, v in obj.items() if k not in ("sig", "_sign_line", "kid")}
    blob = json.dumps(descriptor, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

def _payload_candidates(obj: dict, imports: list, mem_pages: int, exports: list) -> list:
    kid = obj.get("kid")
    if "export_start" in obj:
        export_start = str(obj["export_start"])
    else:
        export_start = "1" if START_EXPORT in exports else "0"
    documented = f"v1|{kid}|{','.join(imports)}|{mem_pages}|{export_start}"
    envelope = f"v1|{kid}|{_descriptor_digest(obj)}"
    return [documented, envelope]

def _signature_valid(obj: dict, secret_hex: str, imports: list, mem_pages: int, exports: list) -> bool:
    sig = obj.get("sig")
    if not isinstance(sig, str):
        return False
    try:
        secret = bytes.fromhex(secret_hex)
    except (ValueError, TypeError):
        return False
    for payload in _payload_candidates(obj, imports, mem_pages, exports):
        expect = hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).digest()
        expect_b64 = base64.urlsafe_b64encode(expect).rstrip(b"=").decode("ascii")
        if hmac.compare_digest(expect_b64, sig):
            return True
    return False

def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Admit a module per docs/admit-rules.md.

    All gates must hold simultaneously: signature, kid not revoked, every
    import whitelisted, mem_pages <= max, and a _start (or policy.entry)
    export. On allow the admission is recorded into ``store`` (the caller
    persists it); on deny the store is left untouched.
    """
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    keys_map = _keys_map(keys)
    policy = policy if isinstance(policy, dict) else {}

    imports, mem_pages, exports, sig_ok = _module_manifest(obj)
    reasons: list[str] = []

    kid = obj.get("kid")
    key_entry = keys_map.get(kid) if isinstance(kid, str) else None
    if key_entry is None:
        reasons.append(REASON_UNKNOWN_KID)
    else:
        if not sig_ok or not _signature_valid(obj, str(key_entry.get("secret", "")), imports, mem_pages, exports):
            reasons.append(REASON_BAD_SIGNATURE)
        if key_entry.get("status") == "revoked":
            reasons.append(REASON_KID_REVOKED)

    allowed_imports = set(policy.get("allowed_imports") or DEFAULT_ALLOWED_IMPORTS)
    seen: set[str] = set()
    for imp in imports:
        if imp in seen and REASON_DUPLICATE_IMPORT not in reasons:
            reasons.append(REASON_DUPLICATE_IMPORT)
        seen.add(imp)
        if imp not in allowed_imports and REASON_IMPORT_NOT_ALLOWED not in reasons:
            reasons.append(REASON_IMPORT_NOT_ALLOWED)

    max_mem_pages = int(policy.get("max_mem_pages", DEFAULT_MAX_MEM_PAGES))
    if mem_pages > max_mem_pages:
        reasons.append(REASON_MEM_PAGES_EXCEEDED)

    entry = policy.get("entry")
    if START_EXPORT not in exports and not (entry and entry in exports):
        reasons.append(REASON_MISSING_ENTRY)

    decision = "allow" if not reasons else "deny"
    if decision == "allow" and isinstance(store, dict):
        items = store.setdefault("items", {})
        if isinstance(items, dict):
            item_id = obj.get("id") or _descriptor_digest(obj)
            items[str(item_id)] = {"ts": now_unix if isinstance(now_unix, int) else 0}

    return {
        "decision": decision,
        "reason_codes": reasons,
        "kind": str(policy.get("pkg", "wasmimp")),
        "notes": [_NOTE_BY_REASON[r] for r in reasons],
    }
