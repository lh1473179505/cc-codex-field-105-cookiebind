from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any


def _b64url(digest: bytes) -> str:
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _hmac_sha256_b64u(key_hex: str, line: str) -> str:
    key = bytes.fromhex(key_hex)
    return _b64url(hmac.new(key, line.encode("ascii"), hashlib.sha256).digest())


def ticket_signing_input(ticket: dict) -> str:
    renewable = 1 if ticket.get("renewable") else 0
    return "v1|{ticket_kid}|{realm}|{cname}|{spn}|{authtime}|{starttime}|{endtime}|{renew_till}|{renewable}|{transited}|{pac_sha256}".format(
        renewable=renewable, **ticket
    )


def pac_digest(pac: dict) -> str:
    blob = json.dumps(pac, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(blob).hexdigest()


def pac_signing_input(pac: dict) -> str:
    group_csv = ",".join(pac.get("group_sids") or [])
    deny_csv = ",".join(pac.get("deny_sids") or [])
    return "v1|{pac_kid}|{logon_domain}|{account}|{groups}|{denies}|{logon_time}|{password_last_set}".format(
        groups=group_csv, denies=deny_csv, **pac
    )


def _key_entry(keyring: dict, kid: Any) -> dict | None:
    if not isinstance(keyring, dict) or not isinstance(kid, str):
        return None
    entry = keyring.get(kid)
    return entry if isinstance(entry, dict) else None


def _check_ticket_gate(ticket: dict, keys: dict, reasons: list[str]) -> None:
    kid = ticket.get("ticket_kid")
    entry = _key_entry(keys.get("ticket_keys"), kid)
    if entry is None:
        reasons.append("ticket_kid_unknown")
        return
    if entry.get("status") != "active":
        reasons.append("ticket_revoked")
        return
    expected = _hmac_sha256_b64u(entry["secret"], ticket_signing_input(ticket))
    if not hmac.compare_digest(expected, str(ticket.get("sig") or "")):
        reasons.append("ticket_sig_invalid")


def _check_pac_gate(ticket: dict, keys: dict, reasons: list[str]) -> None:
    pac = ticket.get("pac")
    if not isinstance(pac, dict):
        reasons.append("pac_digest_mismatch")
        return
    if pac_digest(pac) != ticket.get("pac_sha256"):
        reasons.append("pac_digest_mismatch")
        return
    entry = _key_entry(keys.get("pac_keys"), pac.get("pac_kid"))
    if entry is None:
        reasons.append("pac_kid_unknown")
        return
    if entry.get("status") != "active":
        reasons.append("pac_revoked")
        return
    expected = _hmac_sha256_b64u(entry["secret"], pac_signing_input(pac))
    if not hmac.compare_digest(expected, str(pac.get("sig") or "")):
        reasons.append("pac_sig_invalid")


def _check_account_gate(ticket: dict, policy: dict, reasons: list[str]) -> None:
    if not policy.get("require_pac_account_match"):
        return
    pac = ticket.get("pac")
    if not isinstance(pac, dict) or pac.get("account") != ticket.get("cname"):
        reasons.append("pac_account_mismatch")


def _check_realm_transit_gate(ticket: dict, policy: dict, reasons: list[str]) -> None:
    realm = ticket.get("realm")
    allowed_realms = policy.get("allowed_realms") or []
    if realm not in allowed_realms:
        reasons.append("realm_denied")
    transited = ticket.get("transited") or ""
    if not transited:
        return
    hops = transited.split(",")
    max_hops = policy.get("max_transit_hops")
    if isinstance(max_hops, int) and len(hops) > max_hops:
        reasons.append("transit_denied")
        return
    if policy.get("require_contiguous_transit"):
        if any(hop not in allowed_realms for hop in hops) or hops[-1] != realm:
            reasons.append("transit_denied")


def _check_spn_gate(ticket: dict, policy: dict, reasons: list[str]) -> None:
    realm = ticket.get("realm")
    spn = ticket.get("spn")
    for entry in policy.get("spn_allow") or []:
        if not isinstance(entry, dict) or entry.get("realm") != realm:
            continue
        exact = entry.get("exact")
        if isinstance(exact, str) and spn == exact:
            return
        prefix = entry.get("prefix")
        if isinstance(prefix, str) and isinstance(spn, str) and spn.startswith(prefix):
            return
    reasons.append("spn_denied")


def _check_group_gate(ticket: dict, policy: dict, reasons: list[str]) -> list[str]:
    pac = ticket.get("pac")
    pac = pac if isinstance(pac, dict) else {}
    group_sids = pac.get("group_sids") or []
    deny_sids = pac.get("deny_sids") or []
    allowed = set(policy.get("allowed_group_sids") or [])
    denied = set(policy.get("denied_group_sids") or [])
    matched: list[str] = []
    for sid in group_sids:
        if sid in allowed and sid not in matched:
            matched.append(sid)
    if any(sid in denied for sid in deny_sids):
        reasons.append("sid_denied")
    if not matched:
        reasons.append("group_denied")
    return matched


def _check_time_gate(ticket: dict, policy: dict, now_unix: int, reasons: list[str]) -> None:
    skew = policy.get("clock_skew_seconds") or 0
    starttime = ticket.get("starttime")
    endtime = ticket.get("endtime")
    if not isinstance(starttime, int) or not isinstance(endtime, int):
        reasons.append("time_expired")
        return
    if now_unix < starttime - skew or now_unix > endtime + skew:
        reasons.append("time_expired")


def _check_nonce_gate(ticket: dict, nonce_store: dict, now_unix: int, reasons: list[str]) -> None:
    nonce = ticket.get("nonce")
    known = nonce_store.setdefault("nonces", {})
    if nonce in known:
        reasons.append("replay")
    else:
        known[nonce] = {"ts": now_unix}

def inspect_ticket(ticket: dict) -> dict:
    pac = ticket.get("pac") or {}
    return {
        "realm": ticket.get("realm"),
        "cname": ticket.get("cname"),
        "spn": ticket.get("spn"),
        "ticket_kid": ticket.get("ticket_kid"),
        "pac_kid": pac.get("pac_kid"),
        "group_sids": list(pac.get("group_sids") or []),
        "deny_sids": list(pac.get("deny_sids") or []),
        "endtime": ticket.get("endtime"),
        "nonce": ticket.get("nonce"),
    }

def admit_ticket(ticket: dict, keys: dict, policy: dict, nonce_store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    _check_ticket_gate(ticket, keys, reasons)
    _check_pac_gate(ticket, keys, reasons)
    _check_account_gate(ticket, policy, reasons)
    _check_realm_transit_gate(ticket, policy, reasons)
    _check_spn_gate(ticket, policy, reasons)
    matched_groups = _check_group_gate(ticket, policy, reasons)
    _check_time_gate(ticket, policy, now_unix, reasons)
    _check_nonce_gate(ticket, nonce_store, now_unix, reasons)
    if reasons:
        nonce_store.get("nonces", {}).pop(ticket.get("nonce"), None)
    return {
        "decision": "allow" if not reasons else "deny",
        "reason_codes": reasons,
        "matched_groups": [] if reasons else matched_groups,
        "spn": ticket.get("spn"),
        "realm": ticket.get("realm"),
    }
