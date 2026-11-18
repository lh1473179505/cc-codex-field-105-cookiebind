INITIAL = "prepared"
SOURCE_AFTER = "delegated"
TARGET_AFTER = "acting"
FINAL = "sealed"
STAGE_PHASES = ("prepared", "acting", "delegated")
MIGRATE_PHASES = ("prepared",)
WORK = "work"


def new_session(session_id, subject, authority, artifact, channel, epoch, cursor_id):
    return {
        "id": session_id,
        "subject": subject,
        "authority": authority,
        "artifact": artifact,
        "channel": channel,
        "phase": INITIAL,
        "epoch": epoch,
        "cursor_id": cursor_id,
        "lineage": [],
        WORK: {"tx": None, "payload": {"scope": [], "depth": 0, "marks": []}},
    }


def require_phase(session, allowed):
    if session["phase"] not in allowed:
        raise RuntimeError("phase " + session["phase"] + " does not allow this operation")
