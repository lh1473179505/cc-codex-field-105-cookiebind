"""Business lifecycle; no transport or persistence policy lives here."""
from __future__ import annotations

INITIAL = 'challenged'
SOURCE_AFTER_TRANSFER = 'verified'
TARGET_AFTER_TRANSFER = 'trusted'
FINAL = 'accepted'
STAGE_PHASES = ['challenged', 'trusted', 'verified']
MIGRATE_PHASES = ['challenged']
WORK_KEY = 'assertion'


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
