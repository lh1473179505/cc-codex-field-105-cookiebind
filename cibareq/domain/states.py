"""Business lifecycle; no transport or persistence policy lives here."""
from __future__ import annotations

INITIAL = 'pending'
SOURCE_AFTER_TRANSFER = 'handoff'
TARGET_AFTER_TRANSFER = 'polling'
FINAL = 'redeemed'
STAGE_PHASES = ['pending', 'polling']
MIGRATE_PHASES = ['pending']
WORK_KEY = 'decision'


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
