from __future__ import annotations
import base64
import hashlib
import hmac
import re
from typing import Any

def inspect_mapping(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "rule_id": obj.get("rule_id"),
        "technique_id": obj.get("technique_id"),
        "tactic": obj.get("tactic"),
        "data_source": obj.get("data_source"),
        "evidence_fields": obj.get("evidence_fields"),
        "confidence": obj.get("confidence"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    evidence = ",".join(obj.get("evidence_fields") or [])
    return "|".join([
        "v1",
        str(obj.get("kid")),
        str(obj.get("rule_id")),
        str(obj.get("technique_id")),
        str(obj.get("tactic")),
        str(obj.get("data_source")),
        evidence,
        str(obj.get("confidence")),
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ])

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

def admit_mapping(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    rule_id = obj.get("rule_id")
    codes: list[str] = []

    rules = policy.get("rules") or {}
    techniques = policy.get("techniques") or {}
    rule = rules.get(rule_id)
    if rule is None:
        codes.append("rule")

    technique_id = obj.get("technique_id")
    pattern = policy.get("technique_pattern") or ".*"
    technique = None
    if not isinstance(technique_id, str) or not re.fullmatch(pattern, technique_id):
        codes.append("technique_unknown")
    else:
        technique = techniques.get(technique_id)
        if technique is None:
            codes.append("technique_unknown")

    if rule is not None and technique is not None and technique_id not in (rule.get("techniques") or []):
        codes.append("technique_rule")

    data_source = obj.get("data_source")
    source_fields: list[str] = []
    if technique is not None:
        if obj.get("tactic") not in (technique.get("tactics") or []):
            codes.append("tactic")
        data_sources = technique.get("data_sources") or {}
        if data_source not in data_sources:
            codes.append("data_source")
        else:
            source_fields = data_sources[data_source]

    evidence = obj.get("evidence_fields")
    evidence_list: list[str] = []
    if not isinstance(evidence, list) or any(not isinstance(item, str) for item in evidence):
        codes.append("evidence_unknown")
    else:
        evidence_list = evidence
        if len(set(evidence_list)) != len(evidence_list):
            codes.append("evidence_duplicate")
        count_min = policy.get("evidence_count_min", 0)
        count_max = policy.get("evidence_count_max", len(evidence_list))
        if not (count_min <= len(evidence_list) <= count_max):
            codes.append("evidence_count")
        if technique is not None and data_source in (technique.get("data_sources") or {}):
            if any(item not in source_fields for item in evidence_list):
                codes.append("evidence_unknown")

    confidence = obj.get("confidence")
    confidence_ok = isinstance(confidence, int) and not isinstance(confidence, bool)
    if rule is not None:
        required = rule.get("required_evidence") or []
        if any(item not in evidence_list for item in required):
            codes.append("evidence_required")
        if not confidence_ok or not (rule.get("confidence_min", 0) <= confidence <= rule.get("confidence_max", 100)):
            codes.append("confidence")
        elif confidence >= rule.get("high_confidence_min", 101):
            high_evidence = rule.get("high_confidence_evidence") or []
            if any(item not in evidence_list for item in high_evidence):
                codes.append("high_confidence_evidence")
    elif not confidence_ok:
        codes.append("confidence")

    key_entry = (keys.get("keys") or {}).get(obj.get("kid"))
    if key_entry is None:
        codes.append("key_unknown")
    else:
        if key_entry.get("status") != "active":
            codes.append("revoked")
        expected = _expected_sig(key_entry.get("secret", ""), _signing_line(obj))
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            codes.append("bad_sig")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        codes.append("iat")
    else:
        skew = policy.get("clock_skew_seconds", 0)
        max_age = policy.get("max_age_seconds", 0)
        if iat > now_unix + skew or now_unix - iat > max_age:
            codes.append("iat")

    nonce = obj.get("nonce")
    items = store.get("items") or {}
    if nonce in items:
        codes.append("replay")

    if codes:
        return {"decision": "deny", "reason_codes": codes, "rule_id": rule_id}
    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "rule_id": rule_id}
