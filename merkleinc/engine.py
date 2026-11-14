from __future__ import annotations
import base64
import hashlib
import hmac
import json
from typing import Any

_VERSION = "v1"
_DEFAULT_TRUSTED_ROOTS = ("v1",)
_ENVELOPE_FIELDS = frozenset({"kid", "sig", "_sign_line", "root", "proof"})

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "merkleinc", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}

def _canonical_leaf_sha(leaf: dict) -> str:
    blob = json.dumps(leaf, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()

def _secret_bytes(secret: str) -> bytes:
    try:
        return bytes.fromhex(secret)
    except ValueError:
        return secret.encode("utf-8")

def _expected_sig(secret: str, line: str) -> str:
    digest = hmac.new(_secret_bytes(secret), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Verify an admission object per docs/admit-rules.md.

    Gates: canonical leaf hash, Merkle path L/R recompute, trusted root,
    key revocation, HMAC signature, replay. On allow the store is mutated
    in place (items[id] = {"ts": now_unix}); on deny the store is untouched.
    """
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    if not isinstance(keys, dict) or not isinstance(keys.get("keys"), dict):
        raise ValueError("keys must be an object with a keys object")
    if not isinstance(policy, dict):
        raise ValueError("policy must be an object")
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        raise ValueError("store must be an object with an items object")

    reasons: list[str] = []
    notes: list[str] = []

    def deny(code: str, note: str) -> None:
        if code not in reasons:
            reasons.append(code)
            notes.append(note)

    kid = obj.get("kid")
    sig = obj.get("sig")
    if not isinstance(kid, str) or not isinstance(sig, str):
        deny("malformed_object", "object must carry string kid and sig")

    key_entry = keys["keys"].get(kid) if isinstance(kid, str) else None
    secret = None
    if key_entry is None:
        deny("unknown_kid", f"kid {kid!r} is not in the key ring")
    elif not isinstance(key_entry, dict) or not isinstance(key_entry.get("secret"), str):
        deny("unknown_kid", f"kid {kid!r} has no usable secret")
    else:
        secret = key_entry["secret"]
        if key_entry.get("status") != "active":
            deny("kid_revoked", f"kid {kid!r} is revoked")

    leaf = {k: v for k, v in obj.items() if k not in _ENVELOPE_FIELDS}
    leaf_sha = _canonical_leaf_sha(leaf)

    trusted = policy.get("trusted_roots") or list(_DEFAULT_TRUSTED_ROOTS)
    claimed_root = obj.get("root")
    proof = obj.get("proof")
    explicit_proof = claimed_root is not None or proof is not None
    path_csv = ""
    if explicit_proof:
        if not isinstance(claimed_root, str) or not isinstance(proof, list):
            deny("malformed_proof", "root and proof must be a hex string and a list of steps")
        else:
            current = leaf_sha
            directions: list[str] = []
            steps_ok = True
            for step in proof:
                if not isinstance(step, dict):
                    steps_ok = False
                    break
                direction = step.get("dir")
                sibling = step.get("hash")
                if direction not in ("L", "R") or not isinstance(sibling, str):
                    steps_ok = False
                    break
                directions.append(direction)
                pair = (current + sibling) if direction == "L" else (sibling + current)
                current = hashlib.sha256(pair.encode("utf-8")).hexdigest()
            if not steps_ok:
                deny("bad_path_step", "every proof step needs dir in {L,R} and a hex hash")
            else:
                path_csv = ",".join(directions)
                if current != claimed_root:
                    deny("path_root_mismatch", "recomputed path root does not match claimed root")
            if claimed_root not in trusted:
                deny("untrusted_root", "claimed root is not in policy.trusted_roots")
    else:
        path = leaf.get("path")
        segments = [s for s in path.split("/") if s] if isinstance(path, str) else []
        if not segments:
            deny("empty_path", "leaf path must be /{root}/{pkg}/{steps...}")
        else:
            if segments[0] not in trusted:
                deny("untrusted_root", f"path root {segments[0]!r} is not in policy.trusted_roots")
            pkg = policy.get("pkg")
            if pkg is not None and (len(segments) < 2 or segments[1] != pkg):
                deny("pkg_mismatch", f"path pkg does not match policy pkg {pkg!r}")

    line_parts = [_VERSION, kid if isinstance(kid, str) else "", leaf_sha]
    if explicit_proof:
        line_parts += [claimed_root if isinstance(claimed_root, str) else "", path_csv]
    line = "|".join(line_parts)

    claimed_line = obj.get("_sign_line")
    if claimed_line is not None and claimed_line != line:
        deny("sign_line_mismatch", "claimed _sign_line does not match the reconstructed signing input")

    if secret is not None:
        if not isinstance(sig, str) or not hmac.compare_digest(_expected_sig(secret, line), sig):
            deny("bad_signature", "HMAC-SHA256 signature does not match the canonical signing input")

    obj_id = leaf.get("id")
    if obj_id is not None and obj_id in store["items"]:
        deny("replay", f"id {obj_id!r} is already admitted in the store")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "kind": "merkleinc", "notes": notes}

    store["items"][obj_id if obj_id is not None else leaf_sha] = {"ts": now_unix}
    return {
        "decision": "allow",
        "reason_codes": [],
        "kind": "merkleinc",
        "notes": [],
    }
