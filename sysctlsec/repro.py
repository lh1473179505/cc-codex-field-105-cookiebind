import json
import tempfile
from .database import Database
from .writer import change, InterruptedWrite
from .reboot import recover
from .diagnostics import legacy_view

def main():
    with tempfile.TemporaryDirectory() as tmp:
        db = Database(tmp)
        db.data["active"]["boot-1"] = 4
        try:
            change(db, "kernel", "kernel.randomize_va_space", 0, interrupt=True)
        except InterruptedWrite:
            pass
        recovered = recover(db)
        row = legacy_view(db)["settings"][0]
        print(json.dumps({"recovered": recovered, "setting": row,
                          "untracked_runtime_write": not row["consistent"]}, sort_keys=True))
        return 0 if not recovered and not row["consistent"] else 1
