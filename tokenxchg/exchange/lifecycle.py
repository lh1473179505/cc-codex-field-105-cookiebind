"""Business lifecycle; no transport or persistence policy lives here."""
from __future__ import annotations

INITIAL = 'prepared'
SOURCE_AFTER_TRANSFER = 'delegated'
TARGET_AFTER_TRANSFER = 'acting'
FINAL = 'issued'
STAGE_PHASES = ['prepared', 'acting', 'delegated']
MIGRATE_PHASES = ['prepared']
WORK_KEY = 'delegation'


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
