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
    reachable = current["state"] == "bound" and current["routable"]
    sessions.revoke("beta")
    sessions.detach(new)
    cleaned = sessions.items[new]["state"] == "closed"
    print(json.dumps({"old_session": old, "new_session": new, "sessions": table,
                      "active_session_unreachable": not reachable}, sort_keys=True))
    return 0 if reachable and cleaned else 1
