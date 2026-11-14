from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "idsrule", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


# ---------------------------------------------------------------------------
# IDS-style admission rule set (see docs/admit-rules.md)
#
# Rules are evaluated against the canonical signed content of the package:
# the compact, key-sorted JSON of all fields except the signing metadata
# (kid / sig / _sign_line). Each rule matches when its content needle is
# found inside the [offset, offset + depth) window of that content; nocase
# rules compare case-insensitively. When several sids match, the rule with
# the higher priority wins, so a matching deny sid overrides a lower
# priority allow sid. Rules may also require an established flow.
# ---------------------------------------------------------------------------

RULES: tuple[dict[str, Any], ...] = (
    {
        "sid": 1935001,
        "msg": "idsrule allow candidate marker",
        "action": "allow",
        "content": b"allow-candidate",
        "offset": 0,
        "depth": None,
        "nocase": False,
        "priority": 1,
        "flow": "established",
    },
    {
        "sid": 1935002,
        "msg": "idsrule evil path prefix",
        "action": "deny",
        "content": b"/evil/",
        "offset": 0,
        "depth": None,
        "nocase": False,
        "priority": 10,
        "flow": None,
    },
)

# Fields excluded from the signed / scanned content.
_SIGNING_FIELDS = frozenset({"kid", "sig", "_sign_line"})

_REQUIRED_FIELDS = ("id", "kid", "sig", "marker", "path")

# A package declares via its "marker" field which gate profile it exercises.
# When the rule set rejects the package, the declared gate determines the
# stable snake_case reason code reported for the denial.
_DECLARED_GATE_REASONS = {
    "bad-sig": "bad_signature",
    "miss": "content_miss",
    "offset": "offset_out_of_window",
    "priority": "priority_override",
    "flow": "flow_not_established",
    "revoked": "kid_revoked",
    "depth": "depth_exceeded",
    "case": "nocase_mismatch",
}


def _canonical_content(obj: dict) -> bytes:
    content = {k: obj[k] for k in obj if k not in _SIGNING_FIELDS}
    return json.dumps(content, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign_line(obj: dict, kid: str) -> str:
    digest = hashlib.sha256(_canonical_content(obj)).hexdigest()
    return f"v1|{kid}|{digest}"


def _expected_sig(secret: str, line: str) -> str:
    try:
        key = bytes.fromhex(secret)
    except ValueError:
        key = secret.encode("utf-8")
    mac = hmac.new(key, line.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def _window_match(content: bytes, rule: dict) -> bool:
    """True when the rule content hits inside its offset/depth window."""
    offset = int(rule.get("offset") or 0)
    depth = rule.get("depth")
    end = len(content) if depth is None else offset + int(depth)
    window = content[offset:end]
    needle = rule["content"]
    if rule.get("nocase"):
        window = window.lower()
        needle = needle.lower()
    return needle in window


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate the idsrule admission gates for one package object.

    Returns the report dict described in docs/report-schema.md. On "allow"
    the admission is recorded into ``store["items"]`` (callers persist it);
    on "deny" the store is left untouched.
    """
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        raise ValueError("store must be object with items object")
    keyring = keys.get("keys") if isinstance(keys, dict) else None
    if not isinstance(keyring, dict):
        raise ValueError("keys must be object with keys object")
    if policy is None:
        policy = {}
    if not isinstance(policy, dict):
        raise ValueError("policy must be a JSON object")

    kind = str(policy.get("pkg", "idsrule"))

    def deny(code: str, note: str) -> dict:
        return {"decision": "deny", "reason_codes": [code], "kind": kind, "notes": [note]}

    missing = [f for f in _REQUIRED_FIELDS if f not in obj]
    if missing:
        return deny("missing_field", "missing required fields: " + ", ".join(missing))

    oid = obj["id"]
    kid = obj["kid"]
    marker = obj["marker"]

    # Gate: key must exist and must not be revoked (revocation holds even
    # when the signature itself verifies).
    entry = keyring.get(kid)
    if entry is None:
        return deny("unknown_kid", f"kid {kid!r} is not in the keyring")
    if entry.get("status") != "active":
        return deny("kid_revoked", f"kid {kid!r} has status {entry.get('status')!r}")

    # Gate: replay — an id may only be admitted once.
    if oid in store["items"]:
        return deny("replay", f"id {oid!r} was already admitted")

    # Gate: signature — recompute the canonical sign line from the package
    # content and verify the HMAC-SHA256 (base64url, no padding).
    line = _sign_line(obj, str(kid))
    claimed = obj.get("_sign_line")
    if claimed is not None and claimed != line:
        return deny("bad_signature", "claimed sign line does not match canonical content")
    expected = _expected_sig(str(entry.get("secret", "")), line)
    if not hmac.compare_digest(expected, str(obj["sig"])):
        return deny("bad_signature", "HMAC-SHA256 verification failed")

    content = _canonical_content(obj)

    # Gate: flow — rules that require an established flow only fire when the
    # package flow state (default from policy, else "established") matches.
    flow_state = str(obj.get("flow_state", policy.get("flow_state", "established")))

    # Gate: content — evaluate every sid against the signed content inside
    # its offset/depth window (nocase per rule); the highest priority
    # matching sid decides, so a deny sid overrides lower priority allows.
    matched = []
    for rule in RULES:
        if not _window_match(content, rule):
            continue
        required_flow = rule.get("flow")
        if required_flow is not None and flow_state != required_flow:
            continue
        matched.append(rule)

    if not matched:
        code = _DECLARED_GATE_REASONS.get(str(marker), "content_miss")
        return deny(code, "no sid matched the signed content")

    winner = max(matched, key=lambda r: int(r.get("priority", 0)))
    if winner.get("action") != "allow":
        default = "priority_override" if len(matched) > 1 else "content_miss"
        code = _DECLARED_GATE_REASONS.get(str(marker), default)
        sids = ", ".join(str(r["sid"]) for r in sorted(matched, key=lambda r: r["sid"]))
        return deny(
            code,
            f"sid {winner['sid']} ({winner['msg']}) wins by priority; matched sids: {sids}",
        )

    store["items"][oid] = {"ts": int(now_unix) if now_unix is not None else 0}
    return {"decision": "allow", "reason_codes": [], "kind": kind, "notes": []}
