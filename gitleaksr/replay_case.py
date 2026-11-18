"""Executable end-to-end scenario shared by the CLI reproducer and tests."""
from __future__ import annotations

from .scanner import ScanService


def run_combination() -> dict[str, object]:
    service = ScanService()
    initial = service.snapshot(generation=1, sequence=10, rows=[
        {"key": "item", "scope": "main", "fingerprint": "fp-item", "value": "baseline"},
        {"key": "ghost", "scope": "main", "fingerprint": "fp-ghost", "value": "ghost"},
    ])
    incremental = service.delta(key="other", fingerprint="fp-other", value="delta", sequence=20)
    revoked = service.delta(action="revoke", key="item", fingerprint="fp-item", value="", sequence=30, scope="main")
    revoked_ghost = service.delta(action="revoke", key="ghost", fingerprint="fp-ghost", value="", sequence=31)
    recovery = service.snapshot(generation=2, sequence=40, rows=[
        {"key": "item", "scope": "main", "fingerprint": "fp-item", "value": "recovered"},
    ])
    late = service.delta(key="ghost", fingerprint="fp-ghost", value="late", sequence=35)
    restored = None
    before = service.state_token()
    first = service.report()
    after_first = service.state_token()
    second = service.report()
    after_second = service.state_token()
    expected_identity = "main:item"
    actual = next((row for row in second["items"] if row["scope"] + ":" + row["id"] == expected_identity), None)
    problems: list[str] = []
    if not recovery["accepted"]:
        problems.append("new-generation recovery was rejected")
    if actual is None or actual["value"] != "recovered":
        problems.append("recovered content does not match the current authority")
    if any(row["id"] == "ghost" for row in second["items"]):
        problems.append("an absent revoked record reappeared")
    if late["accepted"]:
        problems.append("a pre-recovery delta crossed the snapshot boundary")
    if before != after_first or before != after_second:
        problems.append("a read-only report changed public state")
    return {
        "service": service,
        "initial": initial,
        "incremental": incremental,
        "revoked": revoked,
        "revoked_ghost": revoked_ghost,
        "recovery": recovery,
        "late": late,
        "restored": restored,
        "before": before,
        "after_first": after_first,
        "after_second": after_second,
        "first": first,
        "second": second,
        "problems": problems,
    }
