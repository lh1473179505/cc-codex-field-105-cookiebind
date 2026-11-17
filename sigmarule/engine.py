from __future__ import annotations

import base64
import hashlib
import hmac


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _signing_message(obj: dict) -> str:
    logsource = obj.get("logsource")
    if not isinstance(logsource, dict):
        logsource = {}
    logsource_part = ",".join(
        f"{key}={logsource[key]}" for key in sorted(logsource)
    )
    detection = obj.get("detection")
    detection_part = ",".join(
        str(item) for item in detection
    ) if isinstance(detection, list) else ""
    field_names = obj.get("field_names")
    field_part = ",".join(
        str(item) for item in field_names
    ) if isinstance(field_names, list) else ""
    return "|".join(
        [
            "v1",
            str(obj.get("kid", "")),
            str(obj.get("rule_id", "")),
            str(obj.get("title", "")),
            logsource_part,
            detection_part,
            str(obj.get("level", "")),
            field_part,
            str(obj.get("iat", "")),
            str(obj.get("nonce", "")),
        ]
    )


def _unique_str_list(value) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) for item in value)
        and len(set(value)) == len(value)
    )


def _missing_required(items: list, required: list) -> list:
    return [item for item in required if item not in items]

def inspect_rule(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "rule_id": obj.get("rule_id"),
        "title": obj.get("title"),
        "logsource": obj.get("logsource"),
        "detection": obj.get("detection"),
        "level": obj.get("level"),
        "field_names": obj.get("field_names"),
        "nonce": obj.get("nonce"),
    }

def admit_rule(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    rule_id = obj.get("rule_id")
    reason_codes: list[str] = []

    rule = policy.get("rules", {}).get(rule_id)
    if rule is None:
        return {
            "decision": "deny",
            "reason_codes": ["rule_id_unknown"],
            "rule_id": rule_id,
        }

    title = obj.get("title")
    if title != rule.get("title"):
        reason_codes.append("title_mismatch")
    if not isinstance(title, str) or len(title) > policy["title_length_max"]:
        reason_codes.append("title_length")

    logsource = obj.get("logsource")
    logsource_keys = policy["logsource_keys"]
    if not isinstance(logsource, dict) or sorted(logsource) != sorted(logsource_keys):
        reason_codes.append("logsource_keys")
    else:
        expected_logsource = rule.get("logsource", {})
        if any(logsource.get(key) != expected_logsource.get(key) for key in logsource_keys):
            reason_codes.append("logsource_mismatch")

    detection = obj.get("detection")
    if not _unique_str_list(detection):
        reason_codes.append("detection_invalid")
        detection_ok = False
    else:
        if not policy["detection_count_min"] <= len(detection) <= policy["detection_count_max"]:
            reason_codes.append("detection_count")
        unknown_detections = [
            item for item in detection if item not in rule["detection_allowed"]
        ]
        if unknown_detections:
            reason_codes.append("detection_unknown")
        if _missing_required(detection, rule.get("detection_required", [])):
            reason_codes.append("detection_required")
        detection_ok = not unknown_detections

    field_names = obj.get("field_names")
    if not _unique_str_list(field_names):
        reason_codes.append("field_names_invalid")
        field_names_ok = False
    else:
        if not policy["field_count_min"] <= len(field_names) <= policy["field_count_max"]:
            reason_codes.append("field_count")
        unknown_fields = [
            item for item in field_names if item not in rule["fields_allowed"]
        ]
        if unknown_fields:
            reason_codes.append("field_unknown")
        if _missing_required(field_names, rule.get("fields_required", [])):
            reason_codes.append("field_required")
        field_names_ok = not unknown_fields

    if detection_ok and field_names_ok:
        selector_fields = rule.get("selector_fields", {})
        for selector in detection:
            missing_fields = [
                field
                for field in selector_fields.get(selector, [])
                if field not in field_names
            ]
            if missing_fields:
                reason_codes.append("selector_field_missing")
                break

    if obj.get("level") not in rule.get("levels", []):
        reason_codes.append("level_unknown")

    key_entry = keys.get("keys", {}).get(obj.get("kid"))
    if key_entry is None:
        reason_codes.append("kid_unknown")
    elif key_entry.get("status") != "active":
        reason_codes.append("key_revoked")
    else:
        try:
            secret = bytes.fromhex(key_entry["secret"])
            expected_sig = _b64url(
                hmac.new(
                    secret,
                    _signing_message(obj).encode("utf-8"),
                    hashlib.sha256,
                ).digest()
            )
            if not hmac.compare_digest(expected_sig, str(obj.get("sig", ""))):
                reason_codes.append("bad_signature")
        except (ValueError, TypeError, KeyError):
            reason_codes.append("bad_signature")

    iat = obj.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, int):
        reason_codes.append("iat_invalid")
    else:
        if iat > now_unix + policy["clock_skew_seconds"]:
            reason_codes.append("iat_future")
        if iat < now_unix - policy["max_age_seconds"]:
            reason_codes.append("iat_expired")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reason_codes.append("nonce_invalid")
    elif nonce in store.get("items", {}):
        reason_codes.append("nonce_replay")

    if reason_codes:
        return {
            "decision": "deny",
            "reason_codes": list(dict.fromkeys(reason_codes)),
            "rule_id": rule_id,
        }

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "rule_id": rule_id}
