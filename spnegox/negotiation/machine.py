"""Business lifecycle; no transport or persistence policy lives here."""
from __future__ import annotations

import copy

INITIAL = 'offered'
SOURCE_AFTER_TRANSFER = 'selected'
TARGET_AFTER_TRANSFER = 'delegated'
FINAL = 'established'
STAGE_PHASES = ['offered', 'delegated', 'selected']
MIGRATE_PHASES = ['offered']
WORK_KEY = 'context'


def new_session(session_id: str, subject: str, authority: str, artifact: str, channel: str, epoch: int) -> dict:
    return {
        "id": session_id,
        "subject": subject,
        "authority": authority,
        "artifact": artifact,
        "channel": channel,
        "phase": INITIAL,
        "epoch": epoch,
        WORK_KEY: {"tx": None, "payload": {}},
        "lineage": [],
    }


def require_phase(session: dict, allowed: tuple[str, ...]) -> None:
    if session["phase"] not in allowed:
        raise RuntimeError(f"phase {session['phase']} does not allow this operation")


def fork_session(session: dict, session_id: str, channel: str, phase: str) -> dict:
    """Create an independent session record for a mechanism hand-off.

    The work container (transaction cursor and mutable payload) and lineage are
    deep copied so the target can never mutate the source's in-flight state.
    """
    target = copy.deepcopy(session)
    target["id"] = session_id
    target["channel"] = channel
    target["phase"] = phase
    target["lineage"] = list(session["lineage"]) + [session["id"]]
    return target
