import json
from .targets import Targets
from .registry import Registry
from .sessions import Sessions
from .migrate import migrate
from .legacy_diag import session_table

def main():
    sessions = Sessions(Targets(), Registry())
    old = sessions.attach("alpha", 7)
    migrate(sessions, old, "beta")
    new = sessions.attach("beta", 7)
    sessions.detach(old)
    table = session_table(sessions)["sessions"]
    current = next(row for row in table if row["session"] == new)
    print(json.dumps({"old_session": old, "new_session": new, "sessions": table,
                      "active_session_unreachable": not current["routable"]}, sort_keys=True))
    return 0 if current["state"] == "bound" and not current["routable"] else 1
