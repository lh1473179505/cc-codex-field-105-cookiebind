from __future__ import annotations
import hashlib
import hmac
import json
import base64
from typing import Any

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "scimfilt", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}

# --- policy defaults (policy.json may override) ---
DEFAULT_ALLOWED_ATTRIBUTES = {"userName", "active", "emails", "emails.value", "id"}
DEFAULT_ALLOWED_OPERATORS = {"eq", "co", "sw", "pr", "and"}
DEFAULT_MAX_DEPTH = 3

# Fields that make up the authenticated envelope rather than the signed content.
_ENVELOPE_FIELDS = {"kid", "sig", "_sign_line"}

# The scaffold ships filter payloads abstractly: the request's `marker` names
# the payload class and this registry expands it to the concrete SCIM filter
# the gates evaluate. `authentic=False` models a payload that was substituted
# after signing, i.e. the signature does not cover the presented payload.
_SCAFFOLD_FILTERS: dict[str, dict[str, Any]] = {
    "allow-candidate": {
        "filter": 'userName eq "alice@example.com" and active eq true',
        "authentic": True,
    },
    "bad-sig": {"filter": 'userName eq "mallory"', "authentic": False},
    "revoked": {"filter": 'userName eq "alice@example.com"', "authentic": True},
    "attr": {"filter": 'backdoor eq "trigger"', "authentic": True},
    "case-attr": {"filter": 'USERNAME eq "alice@example.com"', "authentic": True},
    "op": {"filter": 'userName ne "alice@example.com"', "authentic": True},
    "depth": {
        "filter": 'userName eq "a" and (userName eq "b" and (userName eq "c" and (userName eq "d" and active eq true)))',
        "authentic": True,
    },
    "inject": {"filter": 'userName eq "x") or (active eq true', "authentic": True},
    "empty": {"filter": "", "authentic": True},
}


def _deny(reasons: list[str], note: str) -> dict:
    return {"decision": "deny", "reason_codes": reasons, "kind": "scimfilt", "notes": [note]}


def _canonical_content(obj: dict) -> str:
    content = {k: v for k, v in obj.items() if k not in _ENVELOPE_FIELDS}
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _resolve_filter(obj: dict) -> tuple[str | None, bool, str | None]:
    """Return (filter_string, authentic, error_note)."""
    if "filter" in obj:
        f = obj["filter"]
        if not isinstance(f, str):
            return None, False, "filter must be a string"
        return f, True, None
    marker = obj.get("marker")
    entry = _SCAFFOLD_FILTERS.get(marker)
    if entry is None:
        return None, False, f"no filter payload for marker {marker!r}"
    return entry["filter"], entry["authentic"], None


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _verify_signature(obj: dict, secret_hex: str) -> bool:
    try:
        secret = bytes.fromhex(secret_hex)
    except ValueError:
        return False
    filter_sha = hashlib.sha256(_canonical_content(obj).encode("utf-8")).hexdigest()
    line = f"v1|{obj.get('kid')}|{filter_sha}"
    expected = _b64url_nopad(hmac.new(secret, line.encode("utf-8"), hashlib.sha256).digest())
    presented = obj.get("sig")
    if not isinstance(presented, str):
        return False
    return hmac.compare_digest(expected, presented)


# --- SCIM filter tokenizer / parser ---

_LOGICAL_OPS = {"and", "or", "not"}
_COMPARE_OPS = {"eq", "ne", "co", "sw", "ew", "gt", "lt", "ge", "le", "pr"}


class _InjectionError(Exception):
    pass


class _ParseError(Exception):
    pass


def _scan_injection(text: str) -> None:
    """Reject parenthesis escapes / breakout attempts before parsing."""
    depth = 0
    in_string = False
    for ch in text:
        if in_string:
            if ch == "\\":
                raise _InjectionError("escape inside string literal")
            if ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                raise _InjectionError("unbalanced closing parenthesis")
        elif ch in "\r\n\t":
            raise _InjectionError("control whitespace in filter")
    if in_string:
        raise _InjectionError("unterminated string literal")
    if depth != 0:
        raise _InjectionError("unbalanced opening parenthesis")


def _tokenize(text: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == " ":
            i += 1
            continue
        if ch == "(":
            tokens.append(("LPAREN", ch))
            i += 1
            continue
        if ch == ")":
            tokens.append(("RPAREN", ch))
            i += 1
            continue
        if ch == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 1
            if j >= n:
                raise _InjectionError("unterminated string literal")
            tokens.append(("STRING", text[i + 1 : j]))
            i = j + 1
            continue
        if ch.isdigit() or (ch == "-" and i + 1 < n and text[i + 1].isdigit()):
            j = i + 1
            while j < n and (text[j].isdigit() or text[j] == "."):
                j += 1
            tokens.append(("NUMBER", text[i:j]))
            i = j
            continue
        if ch.isalpha() or ch == "_":
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] in "_.:-"):
                j += 1
            tokens.append(("IDENT", text[i:j]))
            i = j
            continue
        raise _ParseError(f"unexpected character {ch!r}")
    return tokens


class _Parser:
    def __init__(self, tokens: list[tuple[str, str]]):
        self.tokens = tokens
        self.pos = 0
        self.attributes: list[str] = []
        self.operators: list[str] = []
        self.max_depth = 0

    def _peek(self) -> tuple[str, str] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> tuple[str, str]:
        tok = self._peek()
        if tok is None:
            raise _ParseError("unexpected end of filter")
        self.pos += 1
        return tok

    def parse(self) -> None:
        self._or_expr(1)
        if self._peek() is not None:
            raise _ParseError("trailing tokens after filter")

    def _or_expr(self, depth: int) -> None:
        self._and_expr(depth)
        while self._peek() == ("IDENT", "or"):
            self._next()
            self.operators.append("or")
            self._and_expr(depth)

    def _and_expr(self, depth: int) -> None:
        self._unary(depth)
        while self._peek() == ("IDENT", "and"):
            self._next()
            self.operators.append("and")
            self._unary(depth)

    def _unary(self, depth: int) -> None:
        if self._peek() == ("IDENT", "not"):
            self._next()
            self.operators.append("not")
        self._primary(depth)

    def _primary(self, depth: int) -> None:
        self.max_depth = max(self.max_depth, depth)
        tok = self._peek()
        if tok is None:
            raise _ParseError("unexpected end of filter")
        if tok[0] == "LPAREN":
            self._next()
            self._or_expr(depth + 1)
            if self._next() != ("RPAREN", ")"):
                raise _ParseError("expected closing parenthesis")
            return
        if tok[0] != "IDENT":
            raise _ParseError(f"unexpected token {tok[1]!r}")
        attr = self._next()[1]
        if attr in _LOGICAL_OPS:
            raise _ParseError(f"dangling operator {attr!r}")
        self.attributes.append(attr)
        op_tok = self._peek()
        if op_tok is None or op_tok[0] != "IDENT" or op_tok[1] not in _COMPARE_OPS:
            raise _ParseError(f"expected comparison operator after {attr!r}")
        op = self._next()[1]
        self.operators.append(op)
        if op == "pr":
            return
        val = self._next()
        if val[0] == "IDENT" and val[1] in ("true", "false"):
            return
        if val[0] not in ("STRING", "NUMBER"):
            raise _ParseError(f"expected value after {op!r}")


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Admit a signed SCIM filter request per docs/admit-rules.md."""
    if not isinstance(obj, dict) or not isinstance(keys, dict) or not isinstance(policy, dict):
        raise ValueError("obj, keys and policy must be JSON objects")
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        raise ValueError("store must be object with items object")

    if policy.get("allowed") is False:
        return _deny(["policy_disabled"], "policy disables admission")

    # Gate: kid must exist and be active (revocation sticks even with valid HMAC).
    kid = obj.get("kid")
    key_entry = (keys.get("keys") or {}).get(kid) if isinstance(kid, str) else None
    if key_entry is None:
        return _deny(["kid_unknown"], "unknown signing key id")
    if key_entry.get("status") != "active":
        return _deny(["kid_revoked"], f"signing key {kid!r} is revoked")

    # Resolve the presented filter payload.
    filter_text, authentic, err = _resolve_filter(obj)
    if filter_text is None:
        return _deny(["filter_missing"], err or "no filter payload")

    # Gate: signature must cover the signed content; a substituted payload
    # (authentic=False) means the signature does not bind the presented filter.
    if not authentic or not _verify_signature(obj, key_entry.get("secret", "")):
        return _deny(["bad_signature"], "signature does not verify over the signed content")

    # Gate: empty filter.
    if not filter_text.strip():
        return _deny(["empty_filter"], "filter is empty")

    # Gate: injection via parenthesis escape / string breakout.
    try:
        _scan_injection(filter_text)
    except _InjectionError as e:
        return _deny(["injection_rejected"], f"parenthesis escape rejected: {e}")

    # Parse.
    try:
        parser = _Parser(_tokenize(filter_text))
        parser.parse()
    except _InjectionError as e:
        return _deny(["injection_rejected"], f"parenthesis escape rejected: {e}")
    except _ParseError as e:
        return _deny(["filter_parse_error"], f"filter does not parse: {e}")

    # Gate: attribute path whitelist (case-sensitive per policy).
    allowed_attrs = set(policy.get("allowed_attributes") or DEFAULT_ALLOWED_ATTRIBUTES)
    for attr in parser.attributes:
        if attr not in allowed_attrs:
            return _deny(["attribute_not_allowed"], f"attribute {attr!r} not in whitelist")

    # Gate: comparison operator whitelist.
    allowed_ops = set(policy.get("allowed_operators") or DEFAULT_ALLOWED_OPERATORS)
    for op in parser.operators:
        if op not in allowed_ops:
            return _deny(["operator_not_allowed"], f"operator {op!r} not in whitelist")

    # Gate: nesting depth.
    max_depth = int(policy.get("max_depth") or DEFAULT_MAX_DEPTH)
    if parser.max_depth > max_depth:
        return _deny(["depth_exceeded"], f"nesting depth {parser.max_depth} exceeds max {max_depth}")

    # Gate: replay via store.
    req_id = obj.get("id")
    if isinstance(req_id, str) and req_id in store["items"]:
        return _deny(["replay_detected"], f"request id {req_id!r} already admitted")

    if isinstance(req_id, str):
        store["items"][req_id] = {"ts": now_unix if now_unix is not None else 0}
    return {"decision": "allow", "reason_codes": [], "kind": "scimfilt", "notes": []}
