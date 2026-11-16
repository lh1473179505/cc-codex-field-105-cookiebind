from __future__ import annotations
import base64
import hashlib
import hmac
import re
from typing import Any

def inspect_pub(pub: dict) -> dict:
    return {
        "kid": pub.get("kid"),
        "client_id": pub.get("client_id"),
        "cn": pub.get("cn"),
        "topic": pub.get("topic"),
        "qos": pub.get("qos"),
        "retain": pub.get("retain"),
        "nonce": pub.get("nonce"),
    }

def _signing_line(pub: dict) -> str:
    retain = 1 if pub.get("retain") else 0
    return "v1|{kid}|{client_id}|{cn}|{topic}|{qos}|{retain}|{payload_sha256}|{payload_len}|{iat}|{nonce}".format(
        kid=pub.get("kid"),
        client_id=pub.get("client_id"),
        cn=pub.get("cn"),
        topic=pub.get("topic"),
        qos=pub.get("qos"),
        retain=retain,
        payload_sha256=pub.get("payload_sha256"),
        payload_len=pub.get("payload_len"),
        iat=pub.get("iat"),
        nonce=pub.get("nonce"),
    )

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

def _acl_match(topic_filter: str, topic: str) -> bool:
    f_segs = topic_filter.split("/")
    t_segs = topic.split("/")
    if topic.startswith("$") and f_segs and f_segs[0] in ("+", "#"):
        return False
    for i, f_seg in enumerate(f_segs):
        if f_seg == "#":
            return i == len(f_segs) - 1
        if i >= len(t_segs):
            return False
        if f_seg == "+":
            continue
        if f_seg != t_segs[i]:
            return False
    return len(t_segs) == len(f_segs)

def admit_pub(pub: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    topic = pub.get("topic")
    client_id = pub.get("client_id")
    kid = pub.get("kid")

    key_entry = (keys.get("keys") or {}).get(kid)
    if key_entry is None:
        reasons.append("unknown_kid")
    else:
        if key_entry.get("status") != "active":
            reasons.append("key_revoked")
        expected = _expected_sig(key_entry.get("secret", ""), _signing_line(pub))
        if not hmac.compare_digest(expected, str(pub.get("sig"))):
            reasons.append("bad_sig")

    cn_pattern = (policy.get("cn_patterns") or {}).get(client_id)
    if cn_pattern is None or not re.search(cn_pattern, str(pub.get("cn"))):
        reasons.append("cn_mismatch")

    topic_str = str(topic)
    if policy.get("forbid_publish_wildcards") and ("+" in topic_str or "#" in topic_str):
        reasons.append("publish_wildcard")
    if policy.get("forbid_share_prefix") and topic_str.startswith("$share/"):
        reasons.append("share_prefix")
    if policy.get("forbid_sys_prefix") and topic_str.startswith("$SYS/"):
        reasons.append("sys_prefix")
    filters = (policy.get("client_acl") or {}).get(client_id) or []
    if not any(_acl_match(f, topic_str) for f in filters):
        reasons.append("acl_deny")

    qos = pub.get("qos")
    if not isinstance(qos, int) or qos < 0 or qos > policy.get("max_qos", 2):
        reasons.append("qos_exceeded")
    if pub.get("retain"):
        if policy.get("retain_forces_qos0") and qos != 0:
            reasons.append("retain_requires_qos0")
        prefixes = policy.get("retain_allow_prefixes") or []
        if not any(topic_str.startswith(p) for p in prefixes):
            reasons.append("retain_prefix")

    payload_len = pub.get("payload_len")
    if not isinstance(payload_len, int) or payload_len < 0 or payload_len > policy.get("max_payload_bytes", 0):
        reasons.append("payload_too_large")

    iat = pub.get("iat")
    if not isinstance(iat, int):
        reasons.append("iat_invalid")
    else:
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            reasons.append("iat_future")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("iat_expired")

    nonce = pub.get("nonce")
    items = store.get("items") or {}
    if nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "topic": topic}
    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "topic": topic}
