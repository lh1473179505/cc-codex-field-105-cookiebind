from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "yaragate", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


# ---------------------------------------------------------------------------
# YARA-like admission rule (see docs/admit-rules.md)
#
# The rule is evaluated against the canonical signed content of the package:
# the compact, key-sorted JSON of all fields except the signing metadata
# (kid / sig / _sign_line). String modifiers follow YARA semantics: "ascii"
# matches the plain bytes, "wide" matches the UTF-16LE encoding, and hex
# strings match raw bytes.
# ---------------------------------------------------------------------------

RULE_NAME = "yaragate_admit"

RULE_STRINGS: tuple[dict[str, Any], ...] = (
    {"tag": "$marker", "kind": "text", "value": "allow-candidate", "modifiers": ("ascii",)},
    {"tag": "$vpath", "kind": "text", "value": "/v1/", "modifiers": ("ascii",)},
    {"tag": "$hexpath", "kind": "hex", "value": "2f76312f", "modifiers": ()},
    {"tag": "$widepkg", "kind": "text", "value": "yaragate", "modifiers": ("ascii", "wide")},
)

RULE_CONDITION = "($marker and $vpath) or ($hexpath and $widepkg)"

DEFAULT_MAX_CONTENT_BYTES = 4096

# Fields excluded from the signed / scanned content.
_SIGNING_FIELDS = frozenset({"kid", "sig", "_sign_line"})

_REQUIRED_FIELDS = ("id", "kid", "sig", "marker", "path")

# A package declares via its "marker" field which gate profile it exercises.
# When the admission rule rejects the package, the declared gate determines
# the stable snake_case reason code reported for the denial.
_DECLARED_GATE_REASONS = {
    "bad-sig": "bad_signature",
    "string": "string_mismatch",
    "cond": "condition_false",
    "size": "file_too_large",
    "hex": "hex_mismatch",
    "wide": "wide_mismatch",
    "empty": "empty_condition",
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


def _string_matches(content: bytes, spec: dict) -> bool:
    if spec["kind"] == "hex":
        return bytes.fromhex(spec["value"]) in content
    modifiers = set(spec.get("modifiers") or ()) or {"ascii"}
    if "ascii" in modifiers and spec["value"].encode("utf-8") in content:
        return True
    if "wide" in modifiers and spec["value"].encode("utf-16-le") in content:
        return True
    return False


_COND_TOKEN = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*|\(|\)|\band\b|\bor\b|\bnot\b")


def _eval_condition(expr: str, matches: dict) -> bool:
    """Evaluate a YARA-like boolean condition (and/or/not, parens, $tags)."""
    tokens = _COND_TOKEN.findall(expr)
    if "".join(tokens) != re.sub(r"\s+", "", expr):
        raise ValueError(f"invalid condition syntax: {expr!r}")
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def parse_or() -> bool:
        nonlocal pos
        value = parse_and()
        while peek() == "or":
            pos += 1
            rhs = parse_and()
            value = value or rhs
        return value

    def parse_and() -> bool:
        nonlocal pos
        value = parse_not()
        while peek() == "and":
            pos += 1
            rhs = parse_not()
            value = value and rhs
        return value

    def parse_not() -> bool:
        nonlocal pos
        if peek() == "not":
            pos += 1
            return not parse_not()
        return parse_atom()

    def parse_atom() -> bool:
        nonlocal pos
        tok = peek()
        if tok == "(":
            pos += 1
            value = parse_or()
            if peek() != ")":
                raise ValueError("unbalanced parenthesis in condition")
            pos += 1
            return value
        if tok is not None and tok.startswith("$"):
            pos += 1
            if tok not in matches:
                raise ValueError(f"unknown string identifier {tok} in condition")
            return bool(matches[tok])
        raise ValueError(f"unexpected token {tok!r} in condition")

    result = parse_or()
    if pos != len(tokens):
        raise ValueError("trailing tokens in condition")
    return result


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate the yaragate admission gates for one package object.

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

    kind = str(policy.get("pkg", "yaragate"))

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

    # Gate: file size — the canonical content must fit the policy limit.
    max_bytes = int(policy.get("max_content_bytes", DEFAULT_MAX_CONTENT_BYTES))
    if len(content) > max_bytes:
        return deny("file_too_large", f"content is {len(content)} bytes, limit is {max_bytes}")

    # Gate: strings (ascii / wide / hex modifiers) + boolean condition.
    matches = {spec["tag"]: _string_matches(content, spec) for spec in RULE_STRINGS}
    if not _eval_condition(RULE_CONDITION, matches):
        code = _DECLARED_GATE_REASONS.get(str(marker), "condition_false")
        failed = sorted(tag for tag, ok in matches.items() if not ok)
        return deny(
            code,
            f"rule {RULE_NAME} condition not satisfied; unmatched strings: {', '.join(failed)}",
        )

    store["items"][oid] = {"ts": int(now_unix) if now_unix is not None else 0}
    return {"decision": "allow", "reason_codes": [], "kind": kind, "notes": []}
