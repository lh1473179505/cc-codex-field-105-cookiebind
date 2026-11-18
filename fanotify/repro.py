import json
import tempfile
from .broker import Broker
from .dispatcher import open_permission, respond
from .subscriptions import revoke
from .drain import recover
from .audit import legacy_audit

def main():
    with tempfile.TemporaryDirectory() as tmp:
        broker = Broker(tmp)
        event = open_permission(broker, "scan", "/srv/pay/a")
        revoke(broker, "scan")
        rejected = False
        try:
            respond(broker, event, True)
        except PermissionError:
            rejected = True
        recover(broker)
        view = legacy_audit(broker)
        print(json.dumps({"inflight_response_rejected": rejected, "audit": view,
                          "inflight_downgraded": view["decisions"][-1]["decision"] == "deny"}, sort_keys=True))
        return 0 if rejected and view["decisions"][-1]["decision"] == "deny" else 1
