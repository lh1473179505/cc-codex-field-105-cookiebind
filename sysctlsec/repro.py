import json
import tempfile
from .database import Database
from .writer import change, InterruptedWrite
from .reboot import recover, untracked_runtime_writes
from .diagnostics import legacy_view

def main():
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(tmp)
        db.data["active"]["boot-1"] = 4
        epoch_before = db.data["epoch"]
        try:
            change(db, "kernel", "kernel.randomize_va_space", 0, interrupt=True)
        except InterruptedWrite:
            pass
        intent = db.data["intents"][-1]
        interrupted = {
            "status": intent["status"],
            "before_runtime": intent["before_runtime"],
            "before_persistent": intent["before_persistent"],
            "epoch": intent["epoch"],
        }
        recovered = recover(db)
        row = legacy_view(db)["settings"][0]
        untracked = untracked_runtime_writes(db)
        view = legacy_view(db)
        result = {
            "interrupted_intent": interrupted,
            "recovered_tokens": recovered,
            "reused_original_epoch": db.data["epoch"] == epoch_before,
            "setting": row,
            "pending": view["pending"],
            "untracked_runtime_writes": untracked,
        }
        print(json.dumps(result, sort_keys=True))
        return 0 if (row["consistent"] and row["runtime"] == 2 and not untracked
                     and view["pending"] == 0 and result["reused_original_epoch"]) else 1
